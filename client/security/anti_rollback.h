// AntiRollback：防降级判定的接入点（设计 12.2 节第三步，错误码 3003）。
// 判定要用到设备本地保存的 min_security_version 和当前运行的固件版本，
// 这两个值在 boot.json 里（设计 5.2 节），由 A/B 分区那一步实现并提供这个接口的实现。
// manifest 里防降级需要的两个字段 version、security_version 已经在签名保护之下。
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

}  // namespace fwds
