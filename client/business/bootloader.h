// Bootloader：模拟设备上电后的启动过程（设计 4.5 节流程图）。
// 每次“上电”（程序启动）和每次模拟重启都从头走一遍：
//   boot.json 有 pending（刚写好的新固件）：
//       启动次数 +1 → 超过 3 次？→ 验签 pending 分区 → 自检
//       全部通过：pending 转正（active = pending），提升 min_security_version
//       任何一步不过：清除 pending，回到旧分区（回滚）
//   然后启动 active 分区；active 也验不过就试另一个分区；两个都不行进入恢复模式，等服务端推送。
// 新固件只有在自己的分区里验签、自检都通过之后才转正，旧分区在那之前一个字节都没动过，
// 所以升级过程中任何时候出问题，设备都还能用旧固件启动——这就是“不变砖”。
#pragma once

#include <QString>

#include "client/storage/boot_config.h"
#include "client/storage/slot_store.h"
#include "common/manifest.h"
#include "common/protocol.h"
#include "common/security/manifest_verifier.h"

namespace fwds {

// pending 分区最多尝试启动几次；boot_attempts 超过它就回滚（设计 4.5 节）。
inline constexpr int kMaxBootAttempts = 3;

// 一次启动的结论。
struct BootResult {
  enum class Outcome {
    Normal,      // 没有待确认的新固件，照常启动
    Upgraded,    // 新固件验签、自检通过，已转正
    RolledBack,  // 新固件没通过，已回到旧分区
  };
  Outcome outcome = Outcome::Normal;
  BootConfig config;         // 启动结束时的 boot.json
  bool hasFirmware = false;  // false = 恢复模式：两个分区都没有可启动的固件
  Manifest running;          // 正在运行的固件（hasFirmware 为 true 时有效）
  // 以下只在 RolledBack 时有意义
  ErrorCode code = ErrorCode::Ok;  // 3007 自检失败 / 3008 启动失败
  QString detail;
};

class Bootloader {
 public:
  // deviceDir 是设备数据目录；verifier 里已装好 FSK 公钥，必须比 Bootloader 活得久；
  // deviceModel 是本设备的型号。
  Bootloader(const QString& deviceDir, const ManifestVerifier& verifier,
             const QString& deviceModel);

  // 走一遍启动流程，按需要更新 boot.json。
  BootResult boot();

  // 检查一个分区里的固件能不能启动。依次检查：
  //   manifest 签名 → 型号 → security_version 不低于 minSecurityVersion → 整镜像哈希
  //   → （runSelfTest 为 true 时）启动自检
  // 通过返回 Ok，manifest 写入 *manifest；自检失败返回 3007，其余失败返回 3008。
  ErrorCode checkSlot(const QString& slot, int minSecurityVersion, bool runSelfTest,
                      Manifest* manifest, QString* detail) const;

 private:
  void save(const BootConfig& config) const;

  SlotStore slots_;
  const ManifestVerifier& verifier_;
  QString deviceModel_;
};

}  // namespace fwds
