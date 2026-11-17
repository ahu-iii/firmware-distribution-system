// 防降级（设计 12.2 节第三步，UT-08）：安全版本号不低于本机下限，版本号必须比当前新。
#include <gtest/gtest.h>

#include "client/security/anti_rollback.h"

using namespace fwds;

namespace {

Manifest offer(const QString& version, int securityVersion) {
  Manifest m;
  m.version = version;
  m.securityVersion = securityVersion;
  return m;
}

}  // namespace

// UT-08：本地最小安全版本 5、当前版本 2.0.0
TEST(AntiRollbackTest, SecurityVersionBoundary) {
  DeviceAntiRollback guard;
  guard.update(5, QStringLiteral("2.0.0"));
  QString reason;
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("2.1.0"), 4), &reason));  // 低于下限
  EXPECT_FALSE(reason.isEmpty());
  EXPECT_TRUE(guard.allows(offer(QStringLiteral("2.1.0"), 5), &reason));   // 等于下限可以
  EXPECT_TRUE(guard.allows(offer(QStringLiteral("2.1.0"), 6), &reason));
}

TEST(AntiRollbackTest, VersionMustBeNewer) {
  DeviceAntiRollback guard;
  guard.update(5, QStringLiteral("2.0.0"));
  QString reason;
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("1.9.0"), 5), &reason));  // 旧版本
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("2.0.0"), 5), &reason));  // 同一版本
  EXPECT_TRUE(guard.allows(offer(QStringLiteral("2.0.1"), 5), &reason));
  // 按数值逐段比较，不是按字符串：2.10.0 比 2.9.0 新
  guard.update(5, QStringLiteral("2.9.0"));
  EXPECT_TRUE(guard.allows(offer(QStringLiteral("2.10.0"), 5), &reason));
  // 安全版本号更高也不能用来装回旧版本
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("1.0.0"), 9), &reason));
}

// 恢复模式：没有正在运行的固件，只剩安全版本号这一道检查，它仍然有效
TEST(AntiRollbackTest, RecoveryModeStillChecksSecurityVersion) {
  DeviceAntiRollback guard;
  guard.update(5, QString());
  QString reason;
  EXPECT_TRUE(guard.allows(offer(QStringLiteral("1.0.0"), 5), &reason));
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("9.0.0"), 4), &reason));
}

// 版本号比不了（不该发生）时按拒绝处理
TEST(AntiRollbackTest, UnparsableVersionIsRejected) {
  DeviceAntiRollback guard;
  guard.update(1, QStringLiteral("2.0.0"));
  QString reason;
  EXPECT_FALSE(guard.allows(offer(QStringLiteral("latest"), 9), &reason));
}
