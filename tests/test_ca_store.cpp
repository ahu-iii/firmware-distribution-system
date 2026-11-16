// 签发工具 CA 目录操作的单元测试：ca-init、issue-cert、revoke、update-crl。
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/crypto/key_file.h"
#include "common/crypto/x509_util.h"
#include "common/security/cert_verifier.h"
#include "signer/ca_store.h"

using namespace fwds;

namespace {

SecureBuffer secure(const char* text) {
  return SecureBuffer::fromBytes(text, static_cast<int>(strlen(text)));
}

QByteArray readAll(const QString& path) {
  QFile file(path);
  return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

class CaStoreTest : public ::testing::Test {
 protected:
  CaStoreTest() {
    policy.kdfIterations = kKeyFileMinIterations;  // 测试里用最小迭代次数，省时间
  }
  void initCa() {
    ASSERT_TRUE(store().init(QStringLiteral("FWDS Root CA"), 0, caPass, &error)) << error.toStdString();
  }
  CaStore store() const { return CaStore(caDir(), policy); }
  QString caDir() const { return dir.filePath(QStringLiteral("ca")); }

  // 用两端真正使用的校验器检查签发出来的证书
  CertError verify(const IssuedFiles& files, PeerRole role, const QString& expected = QString()) {
    CertVerifier verifier;
    QString e;
    EXPECT_TRUE(verifier.loadCa(readAll(store().caCertPath()), &e)) << e.toStdString();
    EXPECT_TRUE(verifier.loadCrl(readAll(store().crlPath()), &e)) << e.toStdString();
    const X509Ptr cert = certFromPem(files.certPem);
    return verifier.verify(certToDer(cert.get()), role, expected, nullptr).error;
  }

  QTemporaryDir dir;
  SignerPolicy policy;
  SecureBuffer caPass = secure("ca passphrase for tests");
  SecureBuffer keyPass = secure("leaf key passphrase 01");
  QString error;
};

}  // namespace

TEST_F(CaStoreTest, InitCreatesEncryptedKeyRootCertAndEmptyCrl) {
  initCa();
  const QByteArray key = readAll(QDir(caDir()).filePath(QStringLiteral("ca.key")));
  EXPECT_TRUE(key.startsWith("FWKY"));          // 自定义的 AES-256-GCM 封装
  EXPECT_FALSE(key.contains("PRIVATE KEY"));    // 不是明文 PEM，也不是 OpenSSL 的 CBC 加密 PEM

  const X509Ptr ca = certFromPem(readAll(store().caCertPath()));
  ASSERT_TRUE(ca);
  EXPECT_EQ(certCommonName(ca.get()), QStringLiteral("FWDS Root CA"));
  EXPECT_EQ(certNotBefore(ca.get()).secsTo(certNotAfter(ca.get())), 365 * 24 * 3600);  // 默认取上限

  const X509CrlPtr crl = crlFromPem(readAll(store().crlPath()));
  ASSERT_TRUE(crl);
  EXPECT_EQ(crlNumber(crl.get()), 1);

  QList<IssuedCert> certs;
  ASSERT_TRUE(store().list(&certs, &error));
  EXPECT_TRUE(certs.isEmpty());
}

TEST_F(CaStoreTest, InitRefusesToOverwriteAndChecksInput) {
  initCa();
  EXPECT_FALSE(store().init(QStringLiteral("Another"), 0, caPass, &error));  // 已有 CA

  const CaStore fresh(dir.filePath(QStringLiteral("ca2")), policy);
  CaStore s = fresh;
  EXPECT_FALSE(s.init(QStringLiteral("CA"), 0, secure("short"), &error));   // 口令太短
  EXPECT_FALSE(s.init(QStringLiteral("CA"), 366, caPass, &error));          // 超过有效期上限
  EXPECT_FALSE(s.init(QString(), 0, caPass, &error));
  EXPECT_TRUE(s.init(QStringLiteral("CA"), 30, caPass, &error)) << error.toStdString();
}

TEST_F(CaStoreTest, IssuedCertsPassVerification) {
  initCa();
  IssuedFiles server, device;
  ASSERT_TRUE(store().issue(CertType::Server, QStringLiteral("192.168.10.5"), 0, caPass, keyPass,
                            &server, &error))
      << error.toStdString();
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 30, caPass, keyPass,
                            &device, &error))
      << error.toStdString();

  EXPECT_EQ(verify(server, PeerRole::Server, QStringLiteral("192.168.10.5")), CertError::None);
  EXPECT_EQ(verify(server, PeerRole::Server, QStringLiteral("192.168.10.6")), CertError::NameMismatch);
  EXPECT_EQ(verify(device, PeerRole::Device, QStringLiteral("DEV-001")), CertError::None);
  EXPECT_EQ(verify(device, PeerRole::Server, QStringLiteral("DEV-001")), CertError::WrongPurpose);

  // 有效期：默认取上限 90 天；指定 30 天就是 30 天
  EXPECT_EQ(server.info.notBefore.secsTo(server.info.notAfter), 90 * 24 * 3600);
  EXPECT_EQ(device.info.notBefore.secsTo(device.info.notAfter), 30 * 24 * 3600);

  // 私钥只以封装形式交出来，用签发时的口令能解开，并且和证书是一对
  SecureBuffer pkcs8;
  ASSERT_TRUE(openPrivateKey(device.sealedKey, keyPass, &pkcs8, &error));
  const EvpPkeyPtr key = privateKeyFromPkcs8(pkcs8);
  const X509Ptr cert = certFromPem(device.certPem);
  EXPECT_EQ(X509_check_private_key(cert.get(), key.get()), 1);
  EXPECT_FALSE(openPrivateKey(device.sealedKey, caPass, &pkcs8, &error));

  // 两张证书的密钥、序列号互不相同
  EXPECT_NE(server.sealedKey, device.sealedKey);
  EXPECT_NE(server.info.serialHex, device.info.serialHex);

  QList<IssuedCert> certs;
  ASSERT_TRUE(store().list(&certs, &error));
  ASSERT_EQ(certs.size(), 2);
  EXPECT_EQ(certs[1].name, QStringLiteral("DEV-001"));
  EXPECT_EQ(certs[1].fingerprint, device.info.fingerprint);
}

TEST_F(CaStoreTest, IssueRejectsBadInput) {
  initCa();
  IssuedFiles out;
  // CA 口令不对
  EXPECT_FALSE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 0,
                             secure("wrong ca passphrase!"), keyPass, &out, &error));
  // 超过有效期上限
  EXPECT_FALSE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 91, caPass, keyPass, &out, &error));
  // 私钥口令太短
  EXPECT_FALSE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 0, caPass, secure("short"), &out, &error));
  // 名称里带可能被解释成扩展语法的字符
  EXPECT_FALSE(store().issue(CertType::Device, QStringLiteral("DEV-001,CA:TRUE"), 0, caPass, keyPass, &out, &error));
  EXPECT_FALSE(store().issue(CertType::Server, QStringLiteral("host,IP:10.0.0.1"), 0, caPass, keyPass, &out, &error));
  EXPECT_FALSE(store().issue(CertType::Server, QString(), 0, caPass, keyPass, &out, &error));

  QList<IssuedCert> certs;
  ASSERT_TRUE(store().list(&certs, &error));
  EXPECT_TRUE(certs.isEmpty());  // 失败的签发不留台账
}

// 有效期上限来自配置：上限调小后，签发工具不再签更长的证书
TEST_F(CaStoreTest, ValidityCapFollowsPolicy) {
  initCa();
  policy.leafDays = 10;
  IssuedFiles out;
  EXPECT_FALSE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 11, caPass, keyPass, &out, &error));
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 0, caPass, keyPass, &out, &error));
  EXPECT_EQ(out.info.notBefore.secsTo(out.info.notAfter), 10 * 24 * 3600);
}

TEST_F(CaStoreTest, RevokeByNameUpdatesCrlAndOnlyAffectsThatDevice) {
  initCa();
  IssuedFiles dev1, dev2;
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 0, caPass, keyPass, &dev1, &error));
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-002"), 0, caPass, keyPass, &dev2, &error));

  int count = 0;
  ASSERT_TRUE(store().revoke(QString(), QStringLiteral("DEV-002"), QStringLiteral("设备丢失"), caPass,
                             &count, &error))
      << error.toStdString();
  EXPECT_EQ(count, 1);
  EXPECT_EQ(verify(dev2, PeerRole::Device), CertError::Revoked);
  EXPECT_EQ(verify(dev1, PeerRole::Device), CertError::None);

  const X509CrlPtr crl = crlFromPem(readAll(store().crlPath()));
  EXPECT_EQ(crlNumber(crl.get()), 2);  // 序号递增，两端据此拒绝旧 CRL

  QList<IssuedCert> certs;
  ASSERT_TRUE(store().list(&certs, &error));
  EXPECT_FALSE(certs[0].revoked());
  EXPECT_TRUE(certs[1].revoked());
  EXPECT_EQ(certs[1].revokeReason, QStringLiteral("设备丢失"));

  // 重复吊销、吊销不存在的证书、口令错误都报错
  EXPECT_FALSE(store().revoke(QString(), QStringLiteral("DEV-002"), QString(), caPass, &count, &error));
  EXPECT_FALSE(store().revoke(QStringLiteral("00FF"), QString(), QString(), caPass, &count, &error));
  EXPECT_FALSE(store().revoke(QString(), QString(), QString(), caPass, &count, &error));
  EXPECT_FALSE(store().revoke(dev1.info.serialHex, QString(), QString(), secure("wrong ca passphrase!"),
                              &count, &error));
  EXPECT_EQ(verify(dev1, PeerRole::Device), CertError::None);
}

TEST_F(CaStoreTest, RevokeBySerial) {
  initCa();
  IssuedFiles dev;
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-003"), 0, caPass, keyPass, &dev, &error));
  int count = 0;
  ASSERT_TRUE(store().revoke(dev.info.serialHex.toLower(), QString(), QString(), caPass, &count, &error));
  EXPECT_EQ(verify(dev, PeerRole::Device), CertError::Revoked);
}

TEST_F(CaStoreTest, UpdateCrlKeepsRevocationsAndBumpsNumber) {
  initCa();
  IssuedFiles dev;
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-002"), 0, caPass, keyPass, &dev, &error));
  int count = 0;
  ASSERT_TRUE(store().revoke(QString(), QStringLiteral("DEV-002"), QString(), caPass, &count, &error));
  ASSERT_TRUE(store().updateCrl(caPass, &error)) << error.toStdString();
  const X509CrlPtr crl = crlFromPem(readAll(store().crlPath()));
  EXPECT_EQ(crlNumber(crl.get()), 3);
  EXPECT_EQ(verify(dev, PeerRole::Device), CertError::Revoked);
}

TEST_F(CaStoreTest, WriteIssuedFilesProtectsKeyAndRefusesOverwrite) {
  initCa();
  IssuedFiles dev;
  ASSERT_TRUE(store().issue(CertType::Device, QStringLiteral("DEV-001"), 0, caPass, keyPass, &dev, &error));
  const QString outDir = dir.filePath(QStringLiteral("out/DEV-001"));
  ASSERT_TRUE(writeIssuedFiles(outDir, dev, &error)) << error.toStdString();
  const QDir out(outDir);
  EXPECT_TRUE(out.exists(QStringLiteral("device.pem")));
  EXPECT_TRUE(out.exists(QStringLiteral("ca.pem")));
  EXPECT_TRUE(out.exists(QStringLiteral("crl.pem")));
  EXPECT_EQ(readAll(out.filePath(QStringLiteral("device.key"))), dev.sealedKey);
#ifndef _WIN32
  // 私钥文件只有所有者可读写
  EXPECT_EQ(QFile::permissions(out.filePath(QStringLiteral("device.key"))) &
                (QFileDevice::ReadGroup | QFileDevice::ReadOther | QFileDevice::WriteGroup |
                 QFileDevice::WriteOther),
            QFileDevice::Permissions());
#endif
  EXPECT_FALSE(writeIssuedFiles(outDir, dev, &error));  // 不覆盖已有的证书和私钥
}

TEST(CertNames, Validation) {
  EXPECT_TRUE(isValidCertName(CertType::Device, QStringLiteral("DEV-001")));
  EXPECT_TRUE(isValidCertName(CertType::Device, QStringLiteral("plc_x200_17")));
  EXPECT_FALSE(isValidCertName(CertType::Device, QString()));
  EXPECT_FALSE(isValidCertName(CertType::Device, QStringLiteral("DEV 001")));
  EXPECT_FALSE(isValidCertName(CertType::Device, QStringLiteral("DEV/001")));
  EXPECT_FALSE(isValidCertName(CertType::Device, QString(65, QLatin1Char('a'))));
  EXPECT_TRUE(isValidCertName(CertType::Server, QStringLiteral("127.0.0.1")));
  EXPECT_TRUE(isValidCertName(CertType::Server, QStringLiteral("fwds-server.plant.example")));
  EXPECT_FALSE(isValidCertName(CertType::Server, QStringLiteral("-bad.example")));
  EXPECT_FALSE(isValidCertName(CertType::Server, QStringLiteral("a..b")));
  EXPECT_FALSE(isValidCertName(CertType::Server, QStringLiteral("host name")));
}
