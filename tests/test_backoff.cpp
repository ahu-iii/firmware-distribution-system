#include <gtest/gtest.h>

#include "common/config.h"
#include "common/net/backoff.h"

using namespace fwds;

TEST(Backoff, DefaultSequenceCapsAtThirtySeconds) {
  Backoff backoff(ProtocolParams().reconnectBackoffMs);
  const int expected[] = {1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000};
  for (int value : expected) EXPECT_EQ(backoff.next(), value);
}

TEST(Backoff, ResetStartsOver) {
  Backoff backoff({100, 200, 300});
  EXPECT_EQ(backoff.next(), 100);
  EXPECT_EQ(backoff.next(), 200);
  backoff.reset();
  EXPECT_EQ(backoff.next(), 100);
}
