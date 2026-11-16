// SHA-256 和 RSA-PSS 签名验签的单元测试：对应测试报告 UT-03。
#include <openssl/rsa.h>

#include <gtest/gtest.h>

#include "common/crypto/rsa_pss.h"
#include "common/crypto/sha256.h"
#include "signer/cert_builder.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

namespace {

const QByteArray kMessage = "firmware manifest bytes to be signed";

// 用和产品代码不同的参数签名，用来确认验签时参数是卡死的。
// pss 为 false 时用老的 PKCS#1 v1.5 填充；为 true 时用 PSS，但盐长取 saltLength。
QByteArray signWithOtherParameters(EVP_PKEY* key, const QByteArray& message, bool pss,
                                   int saltLength) {
  const OsslPtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;
  EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key);
  if (pss) {
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLength);
  }
  size_t size = 0;
  const auto* data = reinterpret_cast<const unsigned char*>(message.constData());
  EVP_DigestSign(ctx.get(), nullptr, &size, data, static_cast<size_t>(message.size()));
  QByteArray signature(static_cast<qsizetype>(size), '\0');
  EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(signature.data()), &size, data,
                 static_cast<size_t>(message.size()));
  return signature;
}

EvpPkeyPtr generateRsa2048Key() { return EvpPkeyPtr(EVP_RSA_gen(2048)); }

}  // namespace

// ---------- SHA-256 ----------

// 标准测试向量（FIPS 180-4）：确认封装调用的确实是 SHA-256
TEST(Sha256Test, KnownVectors) {
  EXPECT_EQ(sha256("abc").toHex(),
            QByteArray("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  EXPECT_EQ(sha256("").toHex(),
            QByteArray("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(Sha256Test, IncrementalEqualsOneShot) {
  const QByteArray data = randomBytes(200000);
  Sha256 hasher;
  EXPECT_TRUE(hasher.update(data.left(1)));
  EXPECT_TRUE(hasher.update(data.mid(1, 65536)));
  EXPECT_TRUE(hasher.update(data.mid(65537)));
  EXPECT_EQ(hasher.finish(), sha256(data));
}

TEST(Sha256Test, CannotBeReusedAfterFinish) {
  Sha256 hasher;
  hasher.update("abc");
  EXPECT_EQ(hasher.finish().size(), kSha256Size);
  EXPECT_FALSE(hasher.update("more"));
  EXPECT_TRUE(hasher.finish().isEmpty());
}

// ---------- UT-03 RSA-PSS ----------

TEST(RsaPssTest, SignThenVerify) {
  const QByteArray signature = signWith(sharedFsk(), kMessage);
  EXPECT_EQ(signature.size(), kFskSignatureSize);  // RSA-3072 → 384 字节
  EXPECT_TRUE(rsaPssVerify(sharedFsk().key.get(), kMessage, signature));
}

// 只有公钥也能验签（设备手里只有公钥）
TEST(RsaPssTest, VerifyWithPublicKeyOnly) {
  const EvpPkeyPtr publicKey = publicKeyFromPem(sharedFsk().publicPem);
  ASSERT_TRUE(publicKey);
  EXPECT_TRUE(rsaPssVerify(publicKey.get(), kMessage, signWith(sharedFsk(), kMessage)));
}

// PSS 的盐每次新生成：同一份数据签两次，签名不同，但都能验过
TEST(RsaPssTest, SaltIsFreshForEverySignature) {
  const QByteArray first = signWith(sharedFsk(), kMessage);
  const QByteArray second = signWith(sharedFsk(), kMessage);
  EXPECT_NE(first, second);
  EXPECT_TRUE(rsaPssVerify(sharedFsk().key.get(), kMessage, first));
  EXPECT_TRUE(rsaPssVerify(sharedFsk().key.get(), kMessage, second));
}

// 数据改 1 比特：验签失败
TEST(RsaPssTest, ModifiedMessageIsRejected) {
  const QByteArray signature = signWith(sharedFsk(), kMessage);
  for (qsizetype i = 0; i < kMessage.size(); ++i) {
    EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), flipBit(kMessage, i), signature)) << "byte " << i;
  }
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage + "x", signature));
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), QByteArray(), signature));
}

// 签名改 1 比特、截短、加长、为空：验签失败
TEST(RsaPssTest, ModifiedSignatureIsRejected) {
  const QByteArray signature = signWith(sharedFsk(), kMessage);
  for (qsizetype i = 0; i < signature.size(); i += 7) {
    EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, flipBit(signature, i))) << "byte " << i;
  }
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, signature.left(383)));
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, signature + '\0'));
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, QByteArray()));
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, QByteArray(kFskSignatureSize, '\0')));
}

// 用另一把公钥验签：失败
TEST(RsaPssTest, OtherKeyIsRejected) {
  const QByteArray signature = signWith(sharedFsk(), kMessage);
  EXPECT_FALSE(rsaPssVerify(attackerFsk().key.get(), kMessage, signature));
  // 反过来，攻击者自己签的，用正式公钥验也不过
  EXPECT_FALSE(rsaPssVerify(sharedFsk().key.get(), kMessage, signWith(attackerFsk(), kMessage)));
}

// 密钥类型和长度卡死：不是 RSA-3072 的密钥既不能签也不能验
TEST(RsaPssTest, OnlyRsa3072KeysAreAccepted) {
  EXPECT_TRUE(isRsa3072(sharedFsk().key.get()));
  EXPECT_FALSE(isRsa3072(nullptr));

  const EvpPkeyPtr ecKey = generateEcP256Key();
  const EvpPkeyPtr shortKey = generateRsa2048Key();
  ASSERT_TRUE(ecKey && shortKey);
  EXPECT_FALSE(isRsa3072(ecKey.get()));
  EXPECT_FALSE(isRsa3072(shortKey.get()));

  QByteArray signature;
  QString error;
  EXPECT_FALSE(rsaPssSign(shortKey.get(), kMessage, &signature, &error));
  EXPECT_TRUE(signature.isEmpty());
  EXPECT_FALSE(rsaPssSign(ecKey.get(), kMessage, &signature, &error));

  // RSA-2048 自己按 PSS 签出来的合法签名，也因为密钥长度不对被拒绝
  const QByteArray shortSignature =
      signWithOtherParameters(shortKey.get(), kMessage, true, RSA_PSS_SALTLEN_DIGEST);
  EXPECT_FALSE(rsaPssVerify(shortKey.get(), kMessage, shortSignature));
}

// 填充方式和盐长卡死：同一把私钥用 PKCS#1 v1.5 或别的盐长签出来的签名不接受
TEST(RsaPssTest, OtherPaddingOrSaltLengthIsRejected) {
  EVP_PKEY* key = sharedFsk().key.get();
  const QByteArray pkcs1 = signWithOtherParameters(key, kMessage, false, 0);
  const QByteArray shortSalt = signWithOtherParameters(key, kMessage, true, 20);
  ASSERT_EQ(pkcs1.size(), kFskSignatureSize);
  ASSERT_EQ(shortSalt.size(), kFskSignatureSize);
  EXPECT_FALSE(rsaPssVerify(key, kMessage, pkcs1));
  EXPECT_FALSE(rsaPssVerify(key, kMessage, shortSalt));
  // 对照：参数和产品代码一致时能验过，说明上面两次失败确实是参数造成的
  EXPECT_TRUE(rsaPssVerify(key, kMessage,
                           signWithOtherParameters(key, kMessage, true, RSA_PSS_SALTLEN_DIGEST)));
}

// ---------- 公钥编解码 ----------

TEST(RsaPssTest, PublicKeyPemRoundTripAndFingerprint) {
  const QByteArray pem = sharedFsk().publicPem;
  EXPECT_TRUE(pem.startsWith("-----BEGIN PUBLIC KEY-----"));
  EXPECT_FALSE(pem.contains("PRIVATE"));  // 从私钥对象导出，也只带出公钥

  const EvpPkeyPtr publicKey = publicKeyFromPem(pem);
  ASSERT_TRUE(publicKey);
  const QString fingerprint = publicKeyFingerprintSha256(publicKey.get());
  EXPECT_EQ(fingerprint.size(), 64);
  // 同一把钥匙，从私钥对象算和从公钥对象算，指纹一样；换一把钥匙指纹不同
  EXPECT_EQ(fingerprint, publicKeyFingerprintSha256(sharedFsk().key.get()));
  EXPECT_NE(fingerprint, publicKeyFingerprintSha256(attackerFsk().key.get()));

  EXPECT_FALSE(publicKeyFromPem("not a pem"));
}
