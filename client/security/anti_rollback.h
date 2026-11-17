// AntiRollback：防降级判定（设计 12.2 节第三步，错误码 3003）。
// 攻击者手里可能有一份签名完全合法、但带着已知漏洞的旧固件；只验签拦不住它，所以要看版本：
//   ① security_version 不能低于本机记录的 min_security_version（boot.json，只增不减）；
//   ② version 必须比正在运行的固件新。
// manifest 里的 version、security_version 两个字段都在签名保护之下，攻击者改不了。
#pragma once

#include <QString>

#include "common/manifest.h"

namespace fwds {

class AntiRollback {
 public:
  virtual ~AntiRollback() = default;

  // 这份（已验签的）manifest 是否允许安装：security_version 不低于本地最小值，且 version 比当前新。
  // 不允许时返回 false，reason 说明原因（写本地日志和 ALERT）。
  virtual bool allows(const Manifest& manifest, QString* reason) const = 0;
};

// 设备上实际使用的实现。两个基准值来自 Bootloader 的启动结果，每次启动（含模拟重启）后更新一次。
class DeviceAntiRollback : public AntiRollback {
 public:
  // minSecurityVersion：boot.json 里的最小安全版本号；
  // runningVersion：正在运行的固件版本，恢复模式（没有可运行的固件）时传空串。
  void update(int minSecurityVersion, const QString& runningVersion);

  bool allows(const Manifest& manifest, QString* reason) const override;

 private:
  int minSecurityVersion_ = 0;
  QString runningVersion_;
};

}  // namespace fwds
