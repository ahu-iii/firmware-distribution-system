#include "client/security/anti_rollback.h"

namespace fwds {

void DeviceAntiRollback::update(int minSecurityVersion, const QString& runningVersion) {
  minSecurityVersion_ = minSecurityVersion;
  runningVersion_ = runningVersion;
}

bool DeviceAntiRollback::allows(const Manifest& manifest, QString* reason) const {
  // ① 安全版本号：等于下限可以（同一安全级别的功能更新），低于下限拒绝
  if (manifest.securityVersion < minSecurityVersion_) {
    *reason = QStringLiteral("安全版本号 %1 低于本机最小值 %2")
                  .arg(manifest.securityVersion)
                  .arg(minSecurityVersion_);
    return false;
  }
  // ② 版本号必须更新。恢复模式下没有正在运行的固件，这一条无从比较，只靠第 ① 条
  if (runningVersion_.isEmpty()) return true;
  FirmwareVersion offered;
  FirmwareVersion running;
  // 两个版本号都来自验过签的 manifest，正常不会解析失败；万一失败，按拒绝处理
  if (!parseFirmwareVersion(manifest.version, &offered) ||
      !parseFirmwareVersion(runningVersion_, &running)) {
    *reason = QStringLiteral("版本号无法比较");
    return false;
  }
  if (compareFirmwareVersion(offered, running) <= 0) {
    *reason = QStringLiteral("版本 %1 不比当前运行的 %2 新").arg(manifest.version, runningVersion_);
    return false;
  }
  return true;
}

}  // namespace fwds
