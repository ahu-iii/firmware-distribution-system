// 软件保护（设计第 15 节）：字符串加密、设备许可证、程序签名自校验；以及部署相关的数据库结构版本。
// 对应测试报告 ST-31（程序被改 1 字节）、ST-32（许可证拷到别的机器）、FT-21（回滚时数据库版本保护）。
#include <QDateTime>
#include <QFile>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/crypto/rand.h"
#include "common/obfuscated_string.h"
#include "common/security/exe_signature.h"
#include "common/security/license.h"
#include "server/business/license_verifier.h"
#include "server/storage/database.h"
#include "tests/test_fsk.h"

using namespace fwds;
using fwds_test::attackerFsk;
using fwds_test::sharedFsk;
using fwds_test::signWith;
using fwds_test::trustedVerifier;

namespace {

const QString kHw = QString(64, QLatin1Char('b'));

License sampleLicense(const QString& deviceId = QStringLiteral("DEV-001"), const QString& hw = kHw) {
  License lic;
  lic.deviceId = deviceId;
  lic.hwFingerprint = hw;
  lic.issuedAtMs = QDateTime::currentMSecsSinceEpoch();
  lic.expiresAtMs = lic.issuedAtMs + 24LL * 3600 * 1000;
  return lic;
}

// 和 fwds-signer issue-lic 一样：body → 签名 → 文件
QByteArray issue(const License& lic, const fwds_test::TestFsk& key = sharedFsk()) {
  const QByteArray body = encodeLicenseBody(lic);
  return encodeLicenseFile(body, signWith(key, licenseSignedMessage(body)));
}

// 和 fwds-signer sign-exe 一样：对文件哈希加前缀签名，写到 <文件>.sig
void signFile(const QString& path, const fwds_test::TestFsk& key = sharedFsk()) {
  QByteArray digest;
  QString error;
  ASSERT_TRUE(sha256OfFile(path, &digest, &error));
  QFile sig(exeSignaturePath(path));
  ASSERT_TRUE(sig.open(QIODevice::WriteOnly));
  sig.write(signWith(key, exeSignedMessage(digest)));
}

void writeFile(const QString& path, const QByteArray& bytes) {
  QFile f(path);
  ASSERT_TRUE(f.open(QIODevice::WriteOnly));
  f.write(bytes);
}

}  // namespace

// 字符串加密：解出来和原文一样（含中文和空串）；两个相同的字面量各用自己的密钥
TEST(ObfuscatedString, DecryptsToOriginal) {
  EXPECT_EQ(FWDS_OBF("FWDS-LIC-1"), QByteArray("FWDS-LIC-1"));
  EXPECT_EQ(QString::fromUtf8(FWDS_OBF("程序自校验失败")), QStringLiteral("程序自校验失败"));
  EXPECT_EQ(FWDS_OBF(""), QByteArray());
  constexpr obf::Blob<4> a("abc", 1);
  constexpr obf::Blob<4> b("abc", 2);
  EXPECT_EQ(a.decrypt(), b.decrypt());
  EXPECT_NE(obf::keyByte(1, 0), obf::keyByte(2, 0));
}

TEST(License, ValidLicensePassesAllChecks) {
  License parsed;
  QString error;
  const License lic = sampleLicense();
  ASSERT_TRUE(verifyLicense(issue(lic), trustedVerifier(), &parsed, &error)) << error.toStdString();
  EXPECT_EQ(parsed.deviceId, lic.deviceId);
  EXPECT_EQ(parsed.hwFingerprint, kHw);
  EXPECT_EQ(parsed.expiresAtMs, lic.expiresAtMs);
  EXPECT_TRUE(checkLicense(parsed, QStringLiteral("DEV-001"), kHw, lic.issuedAtMs, &error));
}

// ST-32：拷到别的机器（硬件指纹不同）、换给别的设备、过期，都不通过
TEST(License, WrongMachineWrongDeviceOrExpiredIsRejected) {
  License parsed;
  QString error;
  const License lic = sampleLicense();
  ASSERT_TRUE(verifyLicense(issue(lic), trustedVerifier(), &parsed, &error));
  EXPECT_FALSE(checkLicense(parsed, QStringLiteral("DEV-001"), QString(64, QLatin1Char('c')),
                            lic.issuedAtMs, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("硬件指纹")));
  EXPECT_FALSE(checkLicense(parsed, QStringLiteral("DEV-002"), kHw, lic.issuedAtMs, &error));
  EXPECT_FALSE(checkLicense(parsed, QStringLiteral("DEV-001"), kHw, lic.expiresAtMs, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("过期")));
}

// 改了 body（比如把设备 ID 或到期时间改掉）或用攻击者的密钥签，签名都验不过
TEST(License, TamperedOrForgedLicenseFailsSignature) {
  License parsed;
  QString error;
  const License lic = sampleLicense();
  const QByteArray body = encodeLicenseBody(lic);
  const QByteArray sig = signWith(sharedFsk(), licenseSignedMessage(body));
  QByteArray changed = body;
  changed.replace("DEV-001", "DEV-009");
  EXPECT_FALSE(verifyLicense(encodeLicenseFile(changed, sig), trustedVerifier(), &parsed, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("签名")));
  EXPECT_FALSE(verifyLicense(issue(lic, attackerFsk()), trustedVerifier(), &parsed, &error));
  // 不带前缀直接对 body 签名（例如拿 manifest 的签名方式去签）也不行：用途前缀不同
  EXPECT_FALSE(verifyLicense(encodeLicenseFile(body, signWith(sharedFsk(), body)), trustedVerifier(),
                             &parsed, &error));
  EXPECT_FALSE(verifyLicense(QByteArray("not json"), trustedVerifier(), &parsed, &error));
  EXPECT_FALSE(verifyLicense(QByteArray(kMaxLicenseFileSize + 1, '{'), trustedVerifier(), &parsed, &error));
}

// 设备端启动时的检查：签给本机硬件指纹的许可证能用，签给另一台机器的不能
TEST(License, DeviceStartupCheckBindsToThisMachine) {
  const QString hw = localHardwareFingerprint();
  ASSERT_EQ(hw.size(), 64) << "本机取不到机器标识";
  EXPECT_EQ(hw, localHardwareFingerprint());  // 每次算出来一样
  QTemporaryDir dir;
  const QString mine = dir.filePath(QStringLiteral("mine.lic"));
  const QString other = dir.filePath(QStringLiteral("other.lic"));
  writeFile(mine, issue(sampleLicense(QStringLiteral("DEV-001"), hw)));
  writeFile(other, issue(sampleLicense(QStringLiteral("DEV-001"), QString(64, QLatin1Char('d')))));
  QByteArray bytes;
  QString error;
  EXPECT_TRUE(loadDeviceLicense(mine, trustedVerifier(), QStringLiteral("DEV-001"), &bytes, &error))
      << error.toStdString();
  EXPECT_FALSE(bytes.isEmpty());
  EXPECT_FALSE(loadDeviceLicense(other, trustedVerifier(), QStringLiteral("DEV-001"), &bytes, &error));
  EXPECT_FALSE(loadDeviceLicense(dir.filePath(QStringLiteral("none.lic")), trustedVerifier(),
                                 QStringLiteral("DEV-001"), &bytes, &error));
}

// 服务端的检查不看硬件指纹，只看签名、设备 ID、有效期
TEST(License, ServerVerifierIgnoresHardwareFingerprint) {
  const ManifestVerifier fsk = trustedVerifier();
  FskLicenseVerifier verifier(&fsk);
  EXPECT_EQ(verifier.check(QStringLiteral("DEV-001"), issue(sampleLicense())), QString());
  EXPECT_FALSE(verifier.check(QStringLiteral("DEV-002"), issue(sampleLicense())).isEmpty());
  EXPECT_FALSE(verifier.check(QStringLiteral("DEV-001"), QByteArray()).isEmpty());
}

// ST-31：程序文件改 1 个字节、签名被换、签名文件不全，都判为 Invalid；没有签名文件是 Missing
TEST(ExeSignature, AnySingleByteChangeIsDetected) {
  QTemporaryDir dir;
  const QString exe = dir.filePath(QStringLiteral("fwds-client"));
  const QByteArray program = randomBytes(300 * 1024);  // 比读文件的块（1 MB）小也没关系
  writeFile(exe, program);
  QString error;
  EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Missing);

  signFile(exe);
  EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Ok) << error.toStdString();
  // 头、中间、尾各改一个字节
  for (const qsizetype at : {qsizetype(0), program.size() / 2, program.size() - 1}) {
    writeFile(exe, fwds_test::flipBit(program, at));
    EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Invalid) << at;
  }
  // 在末尾追加数据也算改动
  writeFile(exe, program + QByteArray(1, '\0'));
  EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Invalid);

  // 攻击者改了程序再用自己的密钥重签：公钥对不上
  writeFile(exe, program);
  signFile(exe, attackerFsk());
  EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Invalid);
  // 签名文件截短
  writeFile(exeSignaturePath(exe), QByteArray(100, 'x'));
  EXPECT_EQ(verifyExecutable(exe, trustedVerifier(), &error), ExeCheck::Invalid);
}

// 数据库结构版本：新库写入当前版本；比程序新的库拒绝打开（回滚时忘了恢复备份）
TEST(DatabaseSchema, NewerSchemaIsRefused) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("fwds.db"));
  QString error;
  {
    Database db;
    ASSERT_TRUE(db.open(path, &error)) << error.toStdString();
    EXPECT_EQ(db.schemaVersion(), kSchemaVersion);
    QSqlQuery q(db.handle());
    ASSERT_TRUE(q.exec(QStringLiteral("PRAGMA user_version = %1").arg(kSchemaVersion + 1)));
  }
  Database db;
  EXPECT_FALSE(db.open(path, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("备份"))) << error.toStdString();
}

// 编号出现之前建的库（user_version = 0）照常打开，并补上版本号
TEST(DatabaseSchema, LegacyDatabaseGetsVersionStamped) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("fwds.db"));
  QString error;
  {
    Database db;
    ASSERT_TRUE(db.open(path, &error));
    QSqlQuery q(db.handle());
    ASSERT_TRUE(q.exec(QStringLiteral("PRAGMA user_version = 0")));
  }
  Database db;
  ASSERT_TRUE(db.open(path, &error)) << error.toStdString();
  EXPECT_EQ(db.schemaVersion(), kSchemaVersion);
}
