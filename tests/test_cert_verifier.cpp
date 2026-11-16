// 证书与 CRL 校验函数的单元测试（测试报告 UT-13，设计 10.2 节的四项校验）。
#include <gtest/gtest.h>

#include "common/security/cert_verifier.h"
#include "tests/test_pki.h"

using namespace fwds;
using fwds_test::Identity;
using fwds_test::TestPki;

namespace {

class CertVerifierTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(verifier.loadCa(pki.caPem(), &error)) << error.toStdString();
    ASSERT_TRUE(verifier.loadCrl(pki.crl(), &error)) << error.toStdString();
  }
  CertError check(const Identity& id, PeerRole role, const QString& expected = QString()) {
    return verifier.verify(id.certDer, role, expected, &peer).error;
  }
  TestPki pki;
  CertVerifier verifier;
  PeerIdentity peer;
  QString error;
  const QDateTime now = QDateTime::currentDateTimeUtc();
};

}  // namespace

TEST_F(CertVerifierTest, ValidDeviceCertPassesAndReportsIdentity) {
  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  EXPECT_EQ(check(dev, PeerRole::Device), CertError::None);
  EXPECT_EQ(peer.name, QStringLiteral("DEV-001"));
  EXPECT_EQ(peer.serialHex, dev.serialHex);
  EXPECT_EQ(peer.fingerprint.size(), 64);  // SHA-256 的十六进制
}

TEST_F(CertVerifierTest, ValidServerCertPassesForIpAndHostName) {
  EXPECT_EQ(check(pki.issue(CertType::Server, QStringLiteral("127.0.0.1")), PeerRole::Server,
                  QStringLiteral("127.0.0.1")),
            CertError::None);
  EXPECT_EQ(check(pki.issue(CertType::Server, QStringLiteral("fwds.example")), PeerRole::Server,
                  QStringLiteral("fwds.example")),
            CertError::None);
}

// 签发链：其他 CA 签发的证书（即使名称、用途都对）不被信任
TEST_F(CertVerifierTest, CertFromOtherCaIsRejected) {
  TestPki other(QStringLiteral("Evil CA"));
  EXPECT_EQ(check(other.issue(CertType::Device, QStringLiteral("DEV-001")), PeerRole::Device),
            CertError::UntrustedChain);
  // 同名的假 CA 也不行：信任的是那一把公钥，不是名字
  TestPki sameName;
  EXPECT_EQ(check(sameName.issue(CertType::Server, QStringLiteral("127.0.0.1")), PeerRole::Server,
                  QStringLiteral("127.0.0.1")),
            CertError::UntrustedChain);
}

// 有效期：已过期、尚未生效
TEST_F(CertVerifierTest, ExpiredAndNotYetValidCertsAreRejected) {
  const Identity expired =
      pki.issue(CertType::Device, QStringLiteral("DEV-001"), now.addDays(-10), now.addSecs(-60));
  EXPECT_EQ(check(expired, PeerRole::Device), CertError::NotInValidity);
  const Identity future =
      pki.issue(CertType::Device, QStringLiteral("DEV-001"), now.addDays(1), now.addDays(10));
  EXPECT_EQ(check(future, PeerRole::Device), CertError::NotInValidity);
}

// 有效期上限：默认叶子证书 90 天，超过的不接受；上限可以通过配置调整
TEST_F(CertVerifierTest, OverlongValidityIsRejected) {
  const Identity longLived =
      pki.issue(CertType::Device, QStringLiteral("DEV-001"), now.addSecs(-300), now.addDays(91));
  EXPECT_EQ(check(longLived, PeerRole::Device), CertError::ValidityTooLong);

  CertVerifier relaxed(CertLimits{365, 120});
  ASSERT_TRUE(relaxed.loadCa(pki.caPem(), &error));
  ASSERT_TRUE(relaxed.loadCrl(pki.crl(), &error));
  EXPECT_TRUE(relaxed.verify(longLived.certDer, PeerRole::Device, QString(), nullptr).ok());

  CertVerifier strict(CertLimits{365, 7});
  ASSERT_TRUE(strict.loadCa(pki.caPem(), &error));
  ASSERT_TRUE(strict.loadCrl(pki.crl(), &error));
  const Identity month = pki.issue(CertType::Device, QStringLiteral("DEV-001"));  // 30 天
  EXPECT_EQ(strict.verify(month.certDer, PeerRole::Device, QString(), nullptr).error,
            CertError::ValidityTooLong);
}

// 名称
TEST_F(CertVerifierTest, NameMismatchIsRejected) {
  const Identity server = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  EXPECT_EQ(check(server, PeerRole::Server, QStringLiteral("127.0.0.2")), CertError::NameMismatch);
  EXPECT_EQ(check(server, PeerRole::Server, QStringLiteral("fwds.example")), CertError::NameMismatch);
  EXPECT_EQ(check(server, PeerRole::Server, QString()), CertError::NameMismatch);  // 不给期望名称不算通过

  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-002"));
  EXPECT_EQ(check(dev, PeerRole::Device, QStringLiteral("DEV-001")), CertError::NameMismatch);
  EXPECT_EQ(check(dev, PeerRole::Device, QStringLiteral("DEV-002")), CertError::None);
}

// 用途：设备证书不能当服务端证书用，反过来也不行
TEST_F(CertVerifierTest, WrongPurposeIsRejected) {
  // 一台被攻破的设备拿自己的证书冒充服务端：即使名称碰巧是服务端地址也不行
  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  EXPECT_EQ(check(dev, PeerRole::Server, QStringLiteral("DEV-001")), CertError::WrongPurpose);
  const Identity server = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  EXPECT_EQ(check(server, PeerRole::Device), CertError::WrongPurpose);
}

// 吊销：只拒绝被吊销的那一张，其他证书不受影响
TEST_F(CertVerifierTest, RevokedCertIsRejectedOthersUnaffected) {
  const Identity dev1 = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  const Identity dev2 = pki.issue(CertType::Device, QStringLiteral("DEV-002"));
  ASSERT_EQ(check(dev2, PeerRole::Device), CertError::None);

  ASSERT_TRUE(verifier.loadCrl(pki.crl({dev2.serialHex}), &error)) << error.toStdString();
  EXPECT_EQ(check(dev2, PeerRole::Device), CertError::Revoked);
  EXPECT_EQ(check(dev1, PeerRole::Device), CertError::None);
}

// 被改动的 CRL 拒绝加载
TEST_F(CertVerifierTest, TamperedCrlIsRejected) {
  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-002"));
  const QByteArray good = pki.crl({dev.serialHex});
  // PEM 正文中间改一个字符（等于改了 DER 里的内容），签名就对不上了
  QByteArray bad = good;
  const qsizetype pos = bad.indexOf('\n') + 40;
  bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
  EXPECT_FALSE(verifier.loadCrl(bad, &error));
  // 加载失败不影响已经在用的 CRL
  EXPECT_EQ(check(dev, PeerRole::Device), CertError::None);
  EXPECT_TRUE(verifier.loadCrl(good, &error));
  EXPECT_EQ(check(dev, PeerRole::Device), CertError::Revoked);
}

TEST_F(CertVerifierTest, CrlFromOtherCaIsRejected) {
  TestPki other;
  EXPECT_FALSE(verifier.loadCrl(other.crl(), &error));
}

TEST_F(CertVerifierTest, ExpiredCrlIsRejected) {
  EXPECT_FALSE(verifier.loadCrl(pki.crl({}, -60), &error));
}

// 用旧的 CRL 覆盖新的（想把已吊销的证书“恢复”）：按 CRL 序号拒绝
TEST_F(CertVerifierTest, OlderCrlCannotReplaceNewerOne) {
  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-002"));
  const QByteArray before = pki.crlWithNumber(10);
  const QByteArray after = pki.crlWithNumber(11, {dev.serialHex});
  ASSERT_TRUE(verifier.loadCrl(after, &error));
  EXPECT_FALSE(verifier.loadCrl(before, &error));
  EXPECT_EQ(check(dev, PeerRole::Device), CertError::Revoked);
  EXPECT_EQ(verifier.loadedCrlNumber(), 11);
}

// 没有加载 CRL 时一律拒绝，而不是当作“没被吊销”
TEST(CertVerifier, RefusesEverythingUntilCaAndCrlAreLoaded) {
  TestPki pki;
  const Identity dev = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  CertVerifier verifier;
  QString error;
  EXPECT_EQ(verifier.verify(dev.certDer, PeerRole::Device, QString(), nullptr).error,
            CertError::NotReady);
  ASSERT_TRUE(verifier.loadCa(pki.caPem(), &error));
  EXPECT_EQ(verifier.verify(dev.certDer, PeerRole::Device, QString(), nullptr).error,
            CertError::NotReady);
  EXPECT_FALSE(CertVerifier().loadCrl(pki.crl(), &error));  // 没有 CA 就没法验 CRL 的签名
}

TEST(CertVerifier, GarbageIsRejected) {
  TestPki pki;
  CertVerifier verifier;
  QString error;
  ASSERT_TRUE(verifier.loadCa(pki.caPem(), &error));
  ASSERT_TRUE(verifier.loadCrl(pki.crl(), &error));
  EXPECT_EQ(verifier.verify("not a certificate", PeerRole::Device, QString(), nullptr).error,
            CertError::Malformed);
  EXPECT_FALSE(verifier.loadCa("not a certificate", &error));
  EXPECT_FALSE(verifier.loadCrl("not a crl", &error));
}

// 根证书本身也要合格：叶子证书不能当根证书加载；有效期超过上限的根证书不接受
TEST(CertVerifier, CaCertificateIsChecked) {
  TestPki pki;
  QString error;
  CertVerifier verifier;
  EXPECT_FALSE(verifier.loadCa(pki.issue(CertType::Server, QStringLiteral("127.0.0.1")).certPem, &error));
  CertVerifier strict(CertLimits{7, 7});  // 测试 CA 有效期 30 天
  EXPECT_FALSE(strict.loadCa(pki.caPem(), &error));
}
