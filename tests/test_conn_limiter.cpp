#include <gtest/gtest.h>

#include "server/net/conn_limiter.h"

using namespace fwds;

TEST(ConnLimiter, PerIpLimit) {
  ConnLimiter limiter(10, 2);
  const QHostAddress a(QStringLiteral("10.0.0.1"));
  const QHostAddress b(QStringLiteral("10.0.0.2"));
  EXPECT_TRUE(limiter.tryAcquire(a));
  EXPECT_TRUE(limiter.tryAcquire(a));
  EXPECT_FALSE(limiter.tryAcquire(a));  // 同一 IP 第 3 条被拒
  EXPECT_TRUE(limiter.tryAcquire(b));   // 其他 IP 不受影响
  limiter.release(a);
  EXPECT_TRUE(limiter.tryAcquire(a));   // 释放后可以再连
  EXPECT_EQ(limiter.total(), 3);
}

TEST(ConnLimiter, TotalLimit) {
  ConnLimiter limiter(2, 5);
  EXPECT_TRUE(limiter.tryAcquire(QHostAddress(QStringLiteral("10.0.0.1"))));
  EXPECT_TRUE(limiter.tryAcquire(QHostAddress(QStringLiteral("10.0.0.2"))));
  EXPECT_FALSE(limiter.tryAcquire(QHostAddress(QStringLiteral("10.0.0.3"))));
  EXPECT_EQ(limiter.total(), 2);
}

TEST(ConnLimiter, ReleaseUnknownAddressIsIgnored) {
  ConnLimiter limiter(2, 2);
  limiter.release(QHostAddress(QStringLiteral("10.0.0.9")));
  EXPECT_EQ(limiter.total(), 0);
}
