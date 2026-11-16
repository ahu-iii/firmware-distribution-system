// 固件可信校验的单元测试：manifest 先验签后解析（UT-07）、分片哈希、整镜像校验，
// 以及 ST-18（篡改 manifest）、ST-20（伪造或缺失签名）在函数一级的验证。
#include <QBuffer>
#include <gtest/gtest.h>

#include "common/crypto/sha256.h"
#include "common/security/manifest_verifier.h"
#include "signer/cert_builder.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class ManifestVerifierTest : public ::testing::Test {
 protected:
  // 三片：两片满的，最后一片 100 字节
  QByteArray image = randomBytes(2 * kChunkSize + 100);
  QByteArray raw = serializeManifest(manifestFor(image));
  QByteArray signature = signWith(sharedFsk(), raw);
  ManifestVerifier verifier = trustedVerifier();
  Manifest out;
  QString error;
};

// 第 index 片的字节。
QByteArray chunkOf(const QByteArray& image, int index) {
  return image.mid(static_cast<qsizetype>(index) * kChunkSize, kChunkSize);
}

}  // namespace

// ---------- 公钥装入 ----------

TEST_F(ManifestVerifierTest, LoadsOnlyRsa3072PublicKey) {
  ManifestVerifier v;
  EXPECT_TRUE(v.publicKeyFingerprint().isEmpty());
  EXPECT_FALSE(v.loadPublicKey("garbage", &error));
  EXPECT_FALSE(v.loadPublicKey(publicKeyToPem(generateEcP256Key().get()), &error));
  EXPECT_FALSE(v.loadPublicKey(publicKeyToPem(EvpPkeyPtr(EVP_RSA_gen(2048)).get()), &error));
  EXPECT_TRUE(v.publicKeyFingerprint().isEmpty());

  ASSERT_TRUE(v.loadPublicKey(sharedFsk().publicPem, &error)) << error.toStdString();
  EXPECT_EQ(v.publicKeyFingerprint(), publicKeyFingerprintSha256(sharedFsk().key.get()));
}

// 没装公钥的验签器什么都不放行
TEST_F(ManifestVerifierTest, WithoutPublicKeyNothingVerifies) {
  const ManifestVerifier empty;
  EXPECT_EQ(empty.verify(raw, signature, &out, &error), ManifestCheck::BadSignature);
}

// ---------- UT-07 先验签后解析 ----------

TEST_F(ManifestVerifierTest, ValidSignatureThenParsed) {
  ASSERT_EQ(verifier.verify(raw, signature, &out, &error), ManifestCheck::Ok) << error.toStdString();
  EXPECT_EQ(out.deviceModel, QStringLiteral("PLC-X200"));
  EXPECT_EQ(out.securityVersion, 5);
  EXPECT_EQ(out.chunkCount, 3);
  EXPECT_EQ(out.imageSha256, sha256(image));
}

// 签名错误时不解析：输入是一段损坏的 JSON，如果解析器被调用，得到的会是 BadContent
TEST_F(ManifestVerifierTest, BadSignatureNeverReachesParser) {
  const QByteArray broken = "{ this is not json";
  out.pkgId = QStringLiteral("untouched");
  EXPECT_EQ(verifier.verify(broken, signature, &out, &error), ManifestCheck::BadSignature);
  EXPECT_EQ(verifier.verify(broken, signWith(attackerFsk(), broken), &out, &error),
            ManifestCheck::BadSignature);
  EXPECT_EQ(out.pkgId, QStringLiteral("untouched"));
}

// 签名正确但内容不合规：损坏的 JSON、不认识的格式版本
TEST_F(ManifestVerifierTest, ValidSignatureOverBadContent) {
  const QByteArray broken = "{ this is not json";
  EXPECT_EQ(verifier.verify(broken, signWith(sharedFsk(), broken), &out, &error),
            ManifestCheck::BadContent);

  Manifest future = manifestFor(image);
  future.format = 2;
  const QByteArray futureRaw = serializeManifest(future);
  out.pkgId = QStringLiteral("untouched");
  EXPECT_EQ(verifier.verify(futureRaw, signWith(sharedFsk(), futureRaw), &out, &error),
            ManifestCheck::BadContent);
  EXPECT_EQ(out.pkgId, QStringLiteral("untouched"));
}

// ---------- ST-18 篡改 manifest ----------

// manifest 任意位置改 1 比特，验签都失败（每隔几个字节抽一个位置，覆盖所有字段）
TEST_F(ManifestVerifierTest, AnyBitFlipInManifestIsRejected) {
  for (qsizetype i = 0; i < raw.size(); i += 5) {
    EXPECT_EQ(verifier.verify(flipBit(raw, i), signature, &out, &error), ManifestCheck::BadSignature)
        << "byte " << i;
  }
}

// 有针对性的篡改：把安全版本号调高（绕过防降级）、把型号改成别的，JSON 仍然合法，但签名对不上
TEST_F(ManifestVerifierTest, SemanticTamperingIsRejected) {
  QByteArray higher = raw;
  higher.replace("\"security_version\":5", "\"security_version\":9");
  ASSERT_NE(higher, raw);
  EXPECT_EQ(verifier.verify(higher, signature, &out, &error), ManifestCheck::BadSignature);

  QByteArray otherModel = raw;
  otherModel.replace("PLC-X200", "PLC-X300");
  ASSERT_NE(otherModel, raw);
  EXPECT_EQ(verifier.verify(otherModel, signature, &out, &error), ManifestCheck::BadSignature);
}

// ---------- ST-20 伪造或缺失签名 ----------

TEST_F(ManifestVerifierTest, ForgedMissingOrSwappedSignatureIsRejected) {
  // 用攻击者的密钥签名
  EXPECT_EQ(verifier.verify(raw, signWith(attackerFsk(), raw), &out, &error),
            ManifestCheck::BadSignature);
  // 没有签名
  EXPECT_EQ(verifier.verify(raw, QByteArray(), &out, &error), ManifestCheck::BadSignature);
  // 换成另一个合法包的签名
  const QByteArray otherRaw = serializeManifest(manifestFor(randomBytes(1000)));
  const QByteArray otherSignature = signWith(sharedFsk(), otherRaw);
  ASSERT_EQ(verifier.verify(otherRaw, otherSignature, &out, &error), ManifestCheck::Ok);
  EXPECT_EQ(verifier.verify(raw, otherSignature, &out, &error), ManifestCheck::BadSignature);
  // 签名本身改 1 比特
  EXPECT_EQ(verifier.verify(raw, flipBit(signature, 100), &out, &error), ManifestCheck::BadSignature);
}

// ---------- 分片哈希 ----------

TEST_F(ManifestVerifierTest, ChunkMatchesOnlyTheRightBytesAtTheRightIndex) {
  ASSERT_EQ(verifier.verify(raw, signature, &out, &error), ManifestCheck::Ok);
  for (int i = 0; i < 3; ++i) EXPECT_TRUE(chunkMatches(out, i, chunkOf(image, i))) << i;
  EXPECT_EQ(chunkOf(image, 2).size(), 100);

  // 改 1 比特
  EXPECT_FALSE(chunkMatches(out, 0, flipBit(chunkOf(image, 0), 12345)));
  EXPECT_FALSE(chunkMatches(out, 2, flipBit(chunkOf(image, 2), 99)));
  // 内容没错但放错了位置
  EXPECT_FALSE(chunkMatches(out, 1, chunkOf(image, 0)));
  // 长度不对：少一个字节、多一个字节、空
  EXPECT_FALSE(chunkMatches(out, 0, chunkOf(image, 0).left(kChunkSize - 1)));
  EXPECT_FALSE(chunkMatches(out, 2, chunkOf(image, 2) + 'x'));
  EXPECT_FALSE(chunkMatches(out, 0, QByteArray()));
  // 下标越界
  EXPECT_FALSE(chunkMatches(out, -1, chunkOf(image, 0)));
  EXPECT_FALSE(chunkMatches(out, 3, chunkOf(image, 0)));
  EXPECT_FALSE(chunkMatches(out, 3, QByteArray()));
}

// ---------- 整镜像校验 ----------

TEST_F(ManifestVerifierTest, VerifyImageAcceptsIntactImage) {
  ASSERT_EQ(verifier.verify(raw, signature, &out, &error), ManifestCheck::Ok);
  QBuffer buffer(&image);
  ASSERT_TRUE(buffer.open(QIODevice::ReadOnly));
  EXPECT_TRUE(verifyImage(&buffer, out, &error)) << error.toStdString();
}

TEST_F(ManifestVerifierTest, VerifyImageRejectsModifiedOrTruncatedImage) {
  ASSERT_EQ(verifier.verify(raw, signature, &out, &error), ManifestCheck::Ok);

  // 第 1 片里改 1 比特：报出是哪一片
  QByteArray modified = flipBit(image, kChunkSize + 5);
  QBuffer modifiedBuffer(&modified);
  ASSERT_TRUE(modifiedBuffer.open(QIODevice::ReadOnly));
  EXPECT_FALSE(verifyImage(&modifiedBuffer, out, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("第 1 片"))) << error.toStdString();

  // 少一个字节
  QByteArray truncated = image.left(image.size() - 1);
  QBuffer truncatedBuffer(&truncated);
  ASSERT_TRUE(truncatedBuffer.open(QIODevice::ReadOnly));
  EXPECT_FALSE(verifyImage(&truncatedBuffer, out, &error));
}

// 分片哈希全对但整镜像哈希不对的 manifest（只可能来自有缺陷的签发方）：整镜像这一关也要拦住
TEST_F(ManifestVerifierTest, VerifyImageChecksWholeImageDigestToo) {
  Manifest inconsistent = manifestFor(image);
  inconsistent.imageSha256 = sha256("something else");
  QBuffer buffer(&image);
  ASSERT_TRUE(buffer.open(QIODevice::ReadOnly));
  EXPECT_FALSE(verifyImage(&buffer, inconsistent, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("整镜像")));
}
