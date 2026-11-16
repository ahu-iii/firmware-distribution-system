// 签发工具固件签名（fsk-init、sign-fw）和 .fwpkg 容器的单元测试：
// 对应 FT-03（导入验签）、ST-16（私钥文件保护）、ST-19（篡改固件）、ST-20（伪造签名）在函数一级的验证。
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtEndian>
#include <gtest/gtest.h>

#include "common/crypto/key_file.h"
#include "common/crypto/sha256.h"
#include "common/firmware_package.h"
#include "signer/firmware_packer.h"
#include "signer/fsk_store.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

namespace {

SecureBuffer secure(const char* text) {
  return SecureBuffer::fromBytes(text, static_cast<int>(strlen(text)));
}

QByteArray readAll(const QString& path) {
  QFile file(path);
  return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

void writeAll(const QString& path, const QByteArray& content) {
  QFile file(path);
  ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
  ASSERT_EQ(file.write(content), content.size());
}

// .fwpkg 里各字段的偏移，按协议文档 7.2 节算出来。
struct Offsets {
  explicit Offsets(const QByteArray& pkg) {
    manifestLen = qFromBigEndian<quint32>(pkg.constData() + 6);
    manifest = 10;
    sigLen = manifest + manifestLen;
    sig = sigLen + 2;
    imageLen = sig + qFromBigEndian<quint16>(pkg.constData() + sigLen);
    image = imageLen + 8;
  }
  qsizetype manifestLen = 0;
  qsizetype manifest = 0;
  qsizetype sigLen = 0;
  qsizetype sig = 0;
  qsizetype imageLen = 0;
  qsizetype image = 0;
};

class FirmwarePackageTest : public ::testing::Test {
 protected:
  QString path(const char* name) const { return dir.filePath(QString::fromLatin1(name)); }

  // 用 sharedFsk 签出一个正常的包，返回包的全部字节。
  QByteArray makePackage(const QByteArray& imageBytes, const char* name = "fw.fwpkg") {
    writeAll(path("fw.bin"), imageBytes);
    Manifest m;
    EXPECT_TRUE(signFirmware(path("fw.bin"), sampleInfo(), sharedFsk().key.get(), path(name), &m, &error))
        << error.toStdString();
    return readAll(path(name));
  }

  // 把 bytes 写成一个包文件，返回整包检查的结论。
  PackageCheck check(const QByteArray& bytes) {
    writeAll(path("candidate.fwpkg"), bytes);
    return verifyPackageFile(path("candidate.fwpkg"), verifier, &out, &error);
  }

  QTemporaryDir dir;
  QByteArray image = randomBytes(2 * kChunkSize + 100);
  ManifestVerifier verifier = trustedVerifier();
  Manifest out;
  QString error;
};

}  // namespace

// ---------- fsk-init ----------

TEST_F(FirmwarePackageTest, FskInitWritesSealedPrivateKeyAndPublicPem) {
  FskStore store(path("fsk"), kKeyFileMinIterations);  // 测试里用最小迭代次数，省时间
  const SecureBuffer pass = secure("fsk passphrase for tests");
  QString fingerprint;
  ASSERT_TRUE(store.init(pass, &fingerprint, &error)) << error.toStdString();

  // 私钥文件是 AES-256-GCM 封装，不是明文 PEM，也不是 OpenSSL 的 CBC 加密 PEM
  const QByteArray keyFile = readAll(store.privateKeyPath());
  EXPECT_TRUE(keyFile.startsWith("FWKY"));
  EXPECT_FALSE(keyFile.contains("PRIVATE KEY"));
#ifndef _WIN32
  // 私钥文件只有所有者可读写，同组和其他用户没有任何权限
  EXPECT_EQ(QFile::permissions(store.privateKeyPath()) &
                (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ReadOther |
                 QFileDevice::WriteOther),
            QFileDevice::Permissions());
#endif

  // 公钥文件能装进验签器，指纹与 init 报告的一致
  ManifestVerifier fresh;
  ASSERT_TRUE(fresh.loadPublicKey(readAll(store.publicKeyPath()), &error)) << error.toStdString();
  EXPECT_EQ(fresh.publicKeyFingerprint(), fingerprint);

  // 口令正确才能解开；解开的私钥签的名，用公钥文件能验过
  EvpPkeyPtr key;
  EXPECT_FALSE(store.loadPrivateKey(secure("wrong passphrase 000"), &key, &error));
  EXPECT_FALSE(key);
  ASSERT_TRUE(store.loadPrivateKey(pass, &key, &error)) << error.toStdString();
  writeAll(path("fw.bin"), image);
  ASSERT_TRUE(signFirmware(path("fw.bin"), sampleInfo(), key.get(), path("own.fwpkg"), &out, &error));
  EXPECT_EQ(verifyPackageFile(path("own.fwpkg"), fresh, &out, &error), PackageCheck::Ok);

  // 私钥文件被改 1 比特：解不开
  writeAll(store.privateKeyPath(), flipBit(keyFile, keyFile.size() / 2));
  EXPECT_FALSE(store.loadPrivateKey(pass, &key, &error));
}

TEST_F(FirmwarePackageTest, FskInitRefusesWeakPassphraseAndOverwrite) {
  FskStore store(path("fsk"), kKeyFileMinIterations);
  QString fingerprint;
  EXPECT_FALSE(store.init(secure("short"), &fingerprint, &error));
  EXPECT_FALSE(QFile::exists(store.privateKeyPath()));

  ASSERT_TRUE(store.init(secure("fsk passphrase for tests"), &fingerprint, &error));
  const QByteArray before = readAll(store.privateKeyPath());
  EXPECT_FALSE(store.init(secure("another passphrase 01"), &fingerprint, &error));
  EXPECT_EQ(readAll(store.privateKeyPath()), before);  // 原来的密钥没有被动过
}

// ---------- sign-fw ----------

TEST_F(FirmwarePackageTest, PackageIdIsRandomLowercaseUuid) {
  const QString a = newPackageId();
  const QString b = newPackageId();
  EXPECT_NE(a, b);
  EXPECT_EQ(a.size(), 36);
  EXPECT_EQ(a.at(14), QLatin1Char('4'));  // UUID 第 4 版
  Manifest m = manifestFor(image);
  m.pkgId = a;
  EXPECT_TRUE(checkManifest(m, &error)) << error.toStdString();
}

TEST_F(FirmwarePackageTest, SignedPackageVerifiesAndCarriesManifest) {
  const QByteArray pkg = makePackage(image);
  ASSERT_FALSE(pkg.isEmpty());

  // 容器布局与协议文档 7.2 节一致
  const Offsets at(pkg);
  EXPECT_TRUE(pkg.startsWith("FWPK"));
  EXPECT_EQ(qFromBigEndian<quint16>(pkg.constData() + 4), 1);
  EXPECT_EQ(qFromBigEndian<quint16>(pkg.constData() + at.sigLen), kFskSignatureSize);
  EXPECT_EQ(qFromBigEndian<quint64>(pkg.constData() + at.imageLen), static_cast<quint64>(image.size()));
  EXPECT_EQ(pkg.mid(at.image), image);  // 镜像原样在包尾

  ASSERT_EQ(verifyPackageFile(path("fw.fwpkg"), verifier, &out, &error), PackageCheck::Ok)
      << error.toStdString();
  EXPECT_EQ(out.deviceModel, QStringLiteral("PLC-X200"));
  EXPECT_EQ(out.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(out.securityVersion, 5);
  EXPECT_EQ(out.imageSize, image.size());
  EXPECT_EQ(out.imageSha256, sha256(image));
  EXPECT_EQ(out.chunkCount, 3);
  EXPECT_EQ(out.chunkSha256.at(2), sha256(image.right(100)));
}

// 镜像大小的几个边界：1 字节、正好一片、一片多 1 字节
TEST_F(FirmwarePackageTest, ImageSizeBoundaries) {
  int n = 0;
  for (const int size : {1, kChunkSize, kChunkSize + 1}) {
    const QByteArray name = "size" + QByteArray::number(n++) + ".fwpkg";
    ASSERT_FALSE(makePackage(randomBytes(size), name.constData()).isEmpty());
    EXPECT_EQ(verifyPackageFile(path(name.constData()), verifier, &out, &error), PackageCheck::Ok)
        << size << " " << error.toStdString();
    EXPECT_EQ(out.chunkCount, size <= kChunkSize ? 1 : 2);
  }
}

TEST_F(FirmwarePackageTest, SignRefusesBadInputAndLeavesNoOutput) {
  writeAll(path("fw.bin"), image);
  writeAll(path("empty.bin"), QByteArray());
  EVP_PKEY* key = sharedFsk().key.get();

  // 空镜像、镜像不存在
  EXPECT_FALSE(signFirmware(path("empty.bin"), sampleInfo(), key, path("a.fwpkg"), &out, &error));
  EXPECT_FALSE(signFirmware(path("missing.bin"), sampleInfo(), key, path("a.fwpkg"), &out, &error));

  // 元数据不合规
  FirmwareInfo info = sampleInfo();
  info.version = QStringLiteral("2.1");
  EXPECT_FALSE(signFirmware(path("fw.bin"), info, key, path("a.fwpkg"), &out, &error));
  info = sampleInfo();
  info.securityVersion = 0;
  EXPECT_FALSE(signFirmware(path("fw.bin"), info, key, path("a.fwpkg"), &out, &error));
  info = sampleInfo();
  info.deviceModel = QStringLiteral("PLC X200");
  EXPECT_FALSE(signFirmware(path("fw.bin"), info, key, path("a.fwpkg"), &out, &error));

  // 密钥不是 RSA-3072
  const EvpPkeyPtr shortKey(EVP_RSA_gen(2048));
  EXPECT_FALSE(signFirmware(path("fw.bin"), sampleInfo(), shortKey.get(), path("a.fwpkg"), &out, &error));

  EXPECT_FALSE(QFile::exists(path("a.fwpkg")));  // 失败不留下半成品

  // 输出文件已存在：拒绝覆盖
  ASSERT_TRUE(signFirmware(path("fw.bin"), sampleInfo(), key, path("a.fwpkg"), &out, &error));
  const QByteArray before = readAll(path("a.fwpkg"));
  EXPECT_FALSE(signFirmware(path("fw.bin"), sampleInfo(), key, path("a.fwpkg"), &out, &error));
  EXPECT_EQ(readAll(path("a.fwpkg")), before);
}

// ---------- 整包检查：FT-03、ST-19、ST-20 ----------

// manifest 区、签名区改 1 比特：验签失败
TEST_F(FirmwarePackageTest, TamperedManifestOrSignatureIsBadSignature) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);
  EXPECT_EQ(check(flipBit(pkg, at.manifest + 20)), PackageCheck::BadSignature);
  EXPECT_EQ(check(flipBit(pkg, at.manifest + at.manifestLen - 1)), PackageCheck::BadSignature);
  EXPECT_EQ(check(flipBit(pkg, at.sig)), PackageCheck::BadSignature);
  EXPECT_EQ(check(flipBit(pkg, at.sig + kFskSignatureSize - 1)), PackageCheck::BadSignature);
  EXPECT_TRUE(out.pkgId.isEmpty());  // 不通过时不输出 manifest
}

// 镜像区任意位置改 1 比特：哈希不符（ST-19 的函数级版本，每片抽若干位置）
TEST_F(FirmwarePackageTest, TamperedImageIsImageMismatch) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);
  for (qsizetype offset = 0; offset < image.size(); offset += 9973) {
    EXPECT_EQ(check(flipBit(pkg, at.image + offset)), PackageCheck::ImageMismatch) << offset;
  }
  EXPECT_EQ(check(flipBit(pkg, pkg.size() - 1)), PackageCheck::ImageMismatch);  // 最后一个字节
}

// 用攻击者的密钥签出的包，结构完全合法，但过不了正式公钥
TEST_F(FirmwarePackageTest, PackageSignedByAttackerIsBadSignature) {
  writeAll(path("fw.bin"), image);
  ASSERT_TRUE(signFirmware(path("fw.bin"), sampleInfo(), attackerFsk().key.get(), path("fake.fwpkg"),
                           &out, &error));
  Manifest m;
  EXPECT_EQ(verifyPackageFile(path("fake.fwpkg"), verifier, &m, &error), PackageCheck::BadSignature);
}

// 把合法包 A 的 manifest 和签名配上另一个镜像 B：签名能验过，镜像这一关拦住
TEST_F(FirmwarePackageTest, ValidManifestWithOtherImageIsImageMismatch) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);
  const QByteArray manifestRaw = pkg.mid(at.manifest, at.manifestLen);
  const QByteArray signature = pkg.mid(at.sig, kFskSignatureSize);

  // 长度相同、内容不同
  const QByteArray sameSize = randomBytes(static_cast<int>(image.size()));
  EXPECT_EQ(check(buildPackageHeader(manifestRaw, signature, sameSize.size()) + sameSize),
            PackageCheck::ImageMismatch);
  // 长度也不同（容器自身是自洽的，但 image_len 和受签名保护的 image_size 对不上）
  const QByteArray shorter = image.left(1000);
  EXPECT_EQ(check(buildPackageHeader(manifestRaw, signature, shorter.size()) + shorter),
            PackageCheck::ImageMismatch);
}

// 容器结构不对：魔数、格式版本、截断、尾部多出数据
TEST_F(FirmwarePackageTest, MalformedContainerIsRejected) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);
  EXPECT_EQ(check(QByteArray()), PackageCheck::BadContainer);
  EXPECT_EQ(check("FWPK"), PackageCheck::BadContainer);
  EXPECT_EQ(check(flipBit(pkg, 0)), PackageCheck::BadContainer);  // 魔数
  EXPECT_EQ(check(flipBit(pkg, 5)), PackageCheck::BadContainer);  // 格式版本
  EXPECT_EQ(check(pkg.left(pkg.size() - 1)), PackageCheck::BadContainer);   // 少一个字节
  EXPECT_EQ(check(pkg + 'x'), PackageCheck::BadContainer);                  // 多一个字节
  EXPECT_EQ(check(pkg.left(at.sig + 10)), PackageCheck::BadContainer);      // 截在签名中间
  EXPECT_EQ(check(pkg.left(at.manifest + 50)), PackageCheck::BadContainer); // 截在 manifest 中间
  EXPECT_EQ(verifyPackageFile(path("no-such-file.fwpkg"), verifier, &out, &error),
            PackageCheck::BadContainer);
}

// 长度字段写成离谱的值：先校验再读取，不会按它去分配内存
TEST_F(FirmwarePackageTest, HostileLengthFieldsAreRejectedBeforeReading) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);

  QByteArray hugeManifest = pkg;
  qToBigEndian<quint32>(0xFFFFFFFFu, hugeManifest.data() + 6);
  EXPECT_EQ(check(hugeManifest), PackageCheck::BadContainer);

  // 刚好超过上限 1 字节，文件也确实有这么长：仍然拒绝
  QByteArray overLimit = QByteArray("FWPK") + QByteArray(6, '\0') + QByteArray(kMaxManifestSize + 1, ' ');
  qToBigEndian<quint16>(1, overLimit.data() + 4);
  qToBigEndian<quint32>(static_cast<quint32>(kMaxManifestSize + 1), overLimit.data() + 6);
  EXPECT_EQ(check(overLimit), PackageCheck::BadContainer);

  QByteArray zeroManifest = pkg;
  qToBigEndian<quint32>(0, zeroManifest.data() + 6);
  EXPECT_EQ(check(zeroManifest), PackageCheck::BadContainer);

  QByteArray hugeSignature = pkg;
  qToBigEndian<quint16>(0xFFFF, hugeSignature.data() + at.sigLen);
  EXPECT_EQ(check(hugeSignature), PackageCheck::BadContainer);

  QByteArray hugeImage = pkg;
  qToBigEndian<quint64>(0xFFFFFFFFFFFFFFFFull, hugeImage.data() + at.imageLen);
  EXPECT_EQ(check(hugeImage), PackageCheck::BadContainer);

  QByteArray wrongImage = pkg;
  qToBigEndian<quint64>(static_cast<quint64>(image.size() - 1), wrongImage.data() + at.imageLen);
  EXPECT_EQ(check(wrongImage), PackageCheck::BadContainer);
}

// readPackageHeader 原样取出 manifest 字节，并把读位置停在镜像开头
TEST_F(FirmwarePackageTest, ReadHeaderReturnsRawManifestAndImagePosition) {
  const QByteArray pkg = makePackage(image);
  const Offsets at(pkg);
  QFile file(path("fw.fwpkg"));
  ASSERT_TRUE(file.open(QIODevice::ReadOnly));
  PackageHeader header;
  ASSERT_TRUE(readPackageHeader(&file, &header, &error)) << error.toStdString();
  EXPECT_EQ(header.manifestRaw, pkg.mid(at.manifest, at.manifestLen));
  EXPECT_EQ(header.signature.size(), kFskSignatureSize);
  EXPECT_EQ(header.imageOffset, at.image);
  EXPECT_EQ(header.imageSize, image.size());
  EXPECT_EQ(file.pos(), at.image);
  EXPECT_EQ(file.read(16), image.left(16));
}
