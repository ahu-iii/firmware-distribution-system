// boot.json：设备的启动配置（设计 4.5、5.2 节），相当于真实设备 Flash 里 Bootloader 读写的那一小块。
//   active                 当前运行的固件在哪个分区，"a" 或 "b"
//   pending                刚写好、还没确认能启动的新固件在哪个分区；空表示没有
//   boot_attempts          pending 分区已经尝试启动了几次
//   min_security_version   本机接受的最小安全版本号，只增不减（防降级）
// 一律原子写：先写临时文件并刷盘，再改名覆盖。写到一半断电，盘上还是完整的旧文件。
#pragma once

#include <QString>

namespace fwds {

struct BootConfig {
  QString active = QStringLiteral("a");
  QString pending;
  int bootAttempts = 0;
  int minSecurityVersion = 0;
};

// 分区名只有 "a" 和 "b" 两个。
bool isSlotName(const QString& name);
// 另一个分区："a" → "b"，"b" → "a"。
QString otherSlot(const QString& slot);

enum class BootConfigLoad {
  Ok,
  Missing,  // 文件不存在：设备第一次上电
  Corrupt,  // 文件在但内容不合规（不是 JSON、分区名不对、数值为负……）
};

// 读 boot.json。只有返回 Ok 时 out 才被写入。
BootConfigLoad loadBootConfig(const QString& path, BootConfig* out);

// 原子写 boot.json。
bool saveBootConfig(const QString& path, const BootConfig& config, QString* error);

}  // namespace fwds
