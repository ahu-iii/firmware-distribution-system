// 设备端下载前检查的单元测试：验签 → 型号 → 防降级 的顺序和各自的错误码（设计 12.2 节）。
// 防降级的判定规则本身（UT-08）在 A/B 分区那一步实现，这里用替身确认接入点的行为。
#include <gtest/gtest.h>

#include "client/security/update_validator.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

namespace {

// 防降级的替身：按预设的结论回答，并记下被问了几次、问的是哪个安全版本号。
class FakeAntiRollback : public AntiRollback {
 public:
  bool allows(const Manifest& manifest, QString* reason) const override {
    ++calls;
    lastSecurityVersion = manifest.securityVersion;
    if (!allow) *reason = QStringLiteral("security_version too low");
    return allow;
  }
  bool allow = true;
  mutable int calls = 0;
  mutable int lastSecurityVersion = 0;
};

class UpdateValidatorTest : public ::testing::Test {
 protected:
  ErrorCode check(const QByteArray& manifestRaw, const QByteArray& sig,
                  const QString& model = QStringLiteral("PLC-X200")) {
    const UpdateValidator validator(verifier, model, antiRollback);
    return validator.check(manifestRaw, sig, &out, &detail);
  }

  QByteArray raw = serializeManifest(manifestFor(randomBytes(1000)));
  QByteArray signature = signWith(sharedFsk(), raw);
  ManifestVerifier verifier = trustedVerifier();
  FakeAntiRollback antiRollback;
  Manifest out;
  QString detail;
};

}  // namespace

TEST_F(UpdateValidatorTest, AcceptsValidUpdate) {
  ASSERT_EQ(check(raw, signature), ErrorCode::Ok) << detail.toStdString();
  EXPECT_EQ(out.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(antiRollback.calls, 1);
  EXPECT_EQ(antiRollback.lastSecurityVersion, 5);  // 交给防降级的是验过签的 manifest
}

// 签名不过：3001，型号和防降级都不再检查，manifest 不输出
TEST_F(UpdateValidatorTest, BadSignatureStopsEverything) {
  EXPECT_EQ(check(flipBit(raw, 30), signature), ErrorCode::SigInvalid);
  EXPECT_EQ(check(raw, signWith(attackerFsk(), raw)), ErrorCode::SigInvalid);
  EXPECT_EQ(check(raw, QByteArray()), ErrorCode::SigInvalid);
  EXPECT_EQ(antiRollback.calls, 0);
  EXPECT_TRUE(out.pkgId.isEmpty());
}

// 签名正确但内容不合规：3014
TEST_F(UpdateValidatorTest, SignedButMalformedManifest) {
  const QByteArray broken = "{}";
  EXPECT_EQ(check(broken, signWith(sharedFsk(), broken)), ErrorCode::ManifestInvalid);
  EXPECT_EQ(antiRollback.calls, 0);
}

// 型号不符：3002，不再问防降级
TEST_F(UpdateValidatorTest, ModelMismatch) {
  EXPECT_EQ(check(raw, signature, QStringLiteral("PLC-X300")), ErrorCode::ModelMismatch);
  EXPECT_EQ(check(raw, signature, QStringLiteral("plc-x200")), ErrorCode::ModelMismatch);  // 区分大小写
  EXPECT_EQ(antiRollback.calls, 0);
  EXPECT_TRUE(out.pkgId.isEmpty());
}

// 防降级不放行：3003，manifest 不输出
TEST_F(UpdateValidatorTest, RollbackAttempt) {
  antiRollback.allow = false;
  EXPECT_EQ(check(raw, signature), ErrorCode::RollbackAttempt);
  EXPECT_EQ(antiRollback.calls, 1);
  EXPECT_TRUE(out.pkgId.isEmpty());
  EXPECT_FALSE(detail.isEmpty());
}

// 新增错误码的名字和处理方式：3xxx 不断开连接
TEST(ProtocolTest, ManifestInvalidErrorCode) {
  EXPECT_STREQ(errorName(ErrorCode::ManifestInvalid), "MANIFEST_INVALID");
  EXPECT_EQ(static_cast<int>(ErrorCode::ManifestInvalid), 3014);
  EXPECT_FALSE(closesConnection(3014));
}
