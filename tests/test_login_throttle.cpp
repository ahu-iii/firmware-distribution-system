// 设备登录失败锁定（设计第 14 节，ST-30 的单元部分）。
#include <gtest/gtest.h>

#include "server/business/login_throttle.h"

using namespace fwds;

namespace {
const qint64 kMinute = 60 * 1000;
const QString kKey = QStringLiteral("id:DEV-001");
}  // namespace

TEST(LoginThrottle, LocksOnFifthFailureWithinWindow) {
  LoginThrottle throttle(5, 5 * kMinute, 10 * kMinute);
  qint64 now = 1000000;
  for (int i = 0; i < 4; ++i) {
    EXPECT_FALSE(throttle.recordFailure(kKey, now));
    now += 1000;
  }
  EXPECT_FALSE(throttle.isLocked(kKey, now));
  EXPECT_TRUE(throttle.recordFailure(kKey, now));  // 第 5 次触发锁定
  EXPECT_TRUE(throttle.isLocked(kKey, now));
  EXPECT_TRUE(throttle.isLocked(kKey, now + 10 * kMinute - 1));
  EXPECT_FALSE(throttle.isLocked(kKey, now + 10 * kMinute));  // 10 分钟后解除
}

TEST(LoginThrottle, OldFailuresFallOutOfWindow) {
  LoginThrottle throttle(5, 5 * kMinute, 10 * kMinute);
  qint64 now = 1000000;
  for (int i = 0; i < 4; ++i) throttle.recordFailure(kKey, now);
  // 5 分钟之后的失败不和前面 4 次累加
  now += 5 * kMinute;
  EXPECT_FALSE(throttle.recordFailure(kKey, now));
  EXPECT_FALSE(throttle.isLocked(kKey, now));
}

TEST(LoginThrottle, KeysAreIndependent) {
  LoginThrottle throttle(2, kMinute, kMinute);
  throttle.recordFailure(QStringLiteral("id:DEV-001"), 1000);
  EXPECT_TRUE(throttle.recordFailure(QStringLiteral("id:DEV-001"), 2000));
  EXPECT_FALSE(throttle.isLocked(QStringLiteral("id:DEV-002"), 2000));
  EXPECT_FALSE(throttle.isLocked(QStringLiteral("ip:10.0.0.1"), 2000));
}

TEST(LoginThrottle, CountsAgainAfterLockExpires) {
  LoginThrottle throttle(2, kMinute, kMinute);
  throttle.recordFailure(kKey, 1000);
  EXPECT_TRUE(throttle.recordFailure(kKey, 2000));
  EXPECT_FALSE(throttle.recordFailure(kKey, 3000));  // 锁定期内不重复触发
  const qint64 later = 2000 + kMinute;
  EXPECT_FALSE(throttle.isLocked(kKey, later));
  EXPECT_FALSE(throttle.recordFailure(kKey, later));      // 解锁后从 1 重新数
  EXPECT_TRUE(throttle.recordFailure(kKey, later + 10));
}

// 大量不同来源各失败一次：过期的记录会被清掉，仍在窗口内的不受影响
TEST(LoginThrottle, ManyKeysDoNotBreakCounting) {
  LoginThrottle throttle(3, kMinute, kMinute);
  for (int i = 0; i < 5000; ++i) {
    throttle.recordFailure(QStringLiteral("ip:10.1.%1.%2").arg(i / 250).arg(i % 250), 1000 + i);
  }
  const qint64 now = 10 * kMinute;
  throttle.recordFailure(kKey, now);
  throttle.recordFailure(kKey, now + 1);
  EXPECT_TRUE(throttle.recordFailure(kKey, now + 2));
}
