// 加密基础件的单元测试：对应测试报告 UT-04（AES-256-GCM）、UT-05（随机数唯一性）、
// UT-14（SecureBuffer 清零）、ST-16（私钥文件保护）和口令派生的基本性质。
#include <QSet>
#include <gtest/gtest.h>

#include "common/crypto/aead_gcm.h"
#include "common/crypto/kdf.h"
#include "common/crypto/key_file.h"
#include "common/crypto/rand.h"
#include "common/crypto/secure_buffer.h"
#include "common/crypto/x509_util.h"
#include "signer/cert_builder.h"

using namespace fwds;

namespace {

SecureBuffer secure(const QByteArray& bytes) {
  return SecureBuffer::fromBytes(bytes.constData(), static_cast<int>(bytes.size()));
}

QByteArray plain(const SecureBuffer& buffer) {
  return QByteArray(reinterpret_cast<const char*>(buffer.data()), buffer.size());
}

// 翻转第 index 个字节的最低位。
QByteArray flipBit(QByteArray bytes, qsizetype index) {
  bytes[index] = static_cast<char>(bytes[index] ^ 0x01);
  return bytes;
}

// 测试里封装私钥用允许的最小迭代次数，省时间；正式使用的默认值是 600 000。
const int kTestIterations = kKeyFileMinIterations;

}  // namespace

// ---------- UT-14 SecureBuffer ----------

TEST(SecureBuffer, WipeZeroesContentInPlace) {
  SecureBuffer buffer = secure("top secret passphrase");
  const unsigned char* where = buffer.data();
  const int size = buffer.size();
  buffer.wipe();  // 析构时调用的就是这个函数
  EXPECT_EQ(buffer.data(), where);  // 没有换地方，清的就是原来那块内存
  for (int i = 0; i < size; ++i) EXPECT_EQ(where[i], 0) << "byte " << i;
}

TEST(SecureBuffer, MoveLeavesSingleCopy) {
  SecureBuffer a = secure("abc");
  SecureBuffer b = std::move(a);
  EXPECT_TRUE(a.isEmpty());  // NOLINT：故意检查被移动后的对象
  EXPECT_EQ(plain(b), QByteArray("abc"));
}

// ---------- UT-04 AES-256-GCM ----------

class GcmTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(aesGcmEncrypt(key, nonce, aad, secure(message), &ciphertext, &tag));
  }
  SecureBuffer key = secure(randomBytes(kGcmKeySize));
  QByteArray nonce = randomBytes(kGcmNonceSize);
  QByteArray aad = "header";
  QByteArray message = "firmware distribution secret payload";
  QByteArray ciphertext;
  QByteArray tag;
};

TEST_F(GcmTest, RoundTrip) {
  EXPECT_EQ(ciphertext.size(), message.size());
  EXPECT_NE(ciphertext, message);
  EXPECT_EQ(tag.size(), kGcmTagSize);
  SecureBuffer out;
  ASSERT_TRUE(aesGcmDecrypt(key, nonce, aad, ciphertext, tag, &out));
  EXPECT_EQ(plain(out), message);
}

// 密文、标签、关联数据、nonce 任何一处翻转 1 比特：解密失败，且不输出任何明文
TEST_F(GcmTest, AnyBitFlipIsRejectedWithoutPlaintext) {
  SecureBuffer out;
  EXPECT_FALSE(aesGcmDecrypt(key, nonce, aad, flipBit(ciphertext, 0), tag, &out));
  EXPECT_TRUE(out.isEmpty());
  EXPECT_FALSE(aesGcmDecrypt(key, nonce, aad, flipBit(ciphertext, ciphertext.size() - 1), tag, &out));
  EXPECT_TRUE(out.isEmpty());
  EXPECT_FALSE(aesGcmDecrypt(key, nonce, aad, ciphertext, flipBit(tag, 5), &out));
  EXPECT_TRUE(out.isEmpty());
  EXPECT_FALSE(aesGcmDecrypt(key, nonce, flipBit(aad, 2), ciphertext, tag, &out));
  EXPECT_TRUE(out.isEmpty());
  EXPECT_FALSE(aesGcmDecrypt(key, flipBit(nonce, 0), aad, ciphertext, tag, &out));
  EXPECT_TRUE(out.isEmpty());
}

TEST_F(GcmTest, WrongKeyIsRejected) {
  SecureBuffer other = secure(randomBytes(kGcmKeySize));
  SecureBuffer out;
  EXPECT_FALSE(aesGcmDecrypt(other, nonce, aad, ciphertext, tag, &out));
  EXPECT_TRUE(out.isEmpty());
}

TEST_F(GcmTest, WrongSizesAreRejected) {
  QByteArray c, t;
  SecureBuffer out;
  EXPECT_FALSE(aesGcmEncrypt(secure(randomBytes(16)), nonce, aad, secure(message), &c, &t));  // AES-128 的密钥长度
  EXPECT_FALSE(aesGcmEncrypt(key, randomBytes(16), aad, secure(message), &c, &t));
  EXPECT_FALSE(aesGcmDecrypt(key, nonce, aad, ciphertext, tag.left(12), &out));  // 截短的标签
}

// ---------- 口令派生 ----------

// RFC 7914 第 11 节给出的 PBKDF2-HMAC-SHA256 测试向量（口令 "passwd"，盐 "salt"，1 次迭代，64 字节）
TEST(Kdf, MatchesPublishedTestVector) {
  SecureBuffer key;
  ASSERT_TRUE(pbkdf2Sha256(secure("passwd"), "salt", 1, 64, &key));
  EXPECT_EQ(plain(key).toHex(),
            QByteArray("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                       "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
}

TEST(Kdf, SaltAndIterationsChangeTheKey) {
  SecureBuffer a, b, c, d;
  ASSERT_TRUE(pbkdf2Sha256(secure("same passphrase"), "salt-one-16bytes", 1000, 32, &a));
  ASSERT_TRUE(pbkdf2Sha256(secure("same passphrase"), "salt-two-16bytes", 1000, 32, &b));
  ASSERT_TRUE(pbkdf2Sha256(secure("same passphrase"), "salt-one-16bytes", 1001, 32, &c));
  ASSERT_TRUE(pbkdf2Sha256(secure("same passphrase"), "salt-one-16bytes", 1000, 32, &d));
  EXPECT_NE(plain(a), plain(b));  // 盐不同，结果不同：相同口令的两个文件看不出口令相同
  EXPECT_NE(plain(a), plain(c));
  EXPECT_EQ(plain(a), plain(d));  // 参数全相同才能重新得到同一把密钥
}

TEST(Kdf, RejectsBadParameters) {
  SecureBuffer key;
  EXPECT_FALSE(pbkdf2Sha256(SecureBuffer(), "salt", 1000, 32, &key));
  EXPECT_FALSE(pbkdf2Sha256(secure("p"), QByteArray(), 1000, 32, &key));
  EXPECT_FALSE(pbkdf2Sha256(secure("p"), "salt", 0, 32, &key));
}

// ---------- UT-05 随机数唯一性 ----------

TEST(Random, TenThousandNoncesAndSaltsAreUnique) {
  QSet<QByteArray> nonces, salts;
  for (int i = 0; i < 10000; ++i) {
    nonces.insert(randomBytes(kGcmNonceSize));
    salts.insert(randomBytes(kKdfSaltSize));
  }
  EXPECT_EQ(nonces.size(), 10000);
  EXPECT_EQ(salts.size(), 10000);
}

// ---------- 私钥文件 ----------

class KeyFileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const EvpPkeyPtr key = generateEcP256Key();
    ASSERT_TRUE(key);
    ASSERT_TRUE(privateKeyToPkcs8(key.get(), &pkcs8));
    ASSERT_TRUE(sealPrivateKey(pkcs8, passphrase, &sealed, &error, kTestIterations))
        << error.toStdString();
  }
  SecureBuffer pkcs8;
  SecureBuffer passphrase = secure("correct horse battery staple");
  QByteArray sealed;
  QString error;
};

TEST_F(KeyFileTest, RoundTrip) {
  SecureBuffer opened;
  ASSERT_TRUE(openPrivateKey(sealed, passphrase, &opened, &error)) << error.toStdString();
  EXPECT_EQ(plain(opened), plain(pkcs8));
  EXPECT_TRUE(privateKeyFromPkcs8(opened));  // 解出来的确实是一把可用的私钥
}

// ST-16：文件里看不到私钥明文，也不是 PEM
TEST_F(KeyFileTest, FileContainsNoPlaintextKey) {
  EXPECT_FALSE(sealed.contains("PRIVATE KEY"));
  EXPECT_FALSE(sealed.contains(plain(pkcs8).mid(8, 16)));
  EXPECT_TRUE(sealed.startsWith("FWKY"));
}

TEST_F(KeyFileTest, WrongPassphraseIsRejected) {
  SecureBuffer opened;
  EXPECT_FALSE(openPrivateKey(sealed, secure("correct horse battery stapla"), &opened, &error));
  EXPECT_TRUE(opened.isEmpty());
}

// ST-16：改动文件任何位置的 1 个字节都解不开（文件头参与认证）
TEST_F(KeyFileTest, AnyModifiedByteIsRejected) {
  for (qsizetype i = 0; i < sealed.size(); ++i) {
    SecureBuffer opened;
    EXPECT_FALSE(openPrivateKey(flipBit(sealed, i), passphrase, &opened, &error)) << "byte " << i;
    EXPECT_TRUE(opened.isEmpty());
  }
}

TEST_F(KeyFileTest, MalformedFilesAreRejectedBeforeDerivation) {
  SecureBuffer opened;
  EXPECT_FALSE(openPrivateKey(QByteArray(), passphrase, &opened, &error));
  EXPECT_FALSE(openPrivateKey(sealed.left(30), passphrase, &opened, &error));            // 截断
  EXPECT_FALSE(openPrivateKey(sealed + QByteArray(1, 'x'), passphrase, &opened, &error));  // 多出数据

  QByteArray hugeLength = sealed;  // 密文长度字段写成 0xFFFFFFFF
  for (int i = 38; i < 42; ++i) hugeLength[i] = static_cast<char>(0xff);
  EXPECT_FALSE(openPrivateKey(hugeLength, passphrase, &opened, &error));

  QByteArray weak = sealed;  // 迭代次数改成 1：不接受弱派生参数
  weak[6] = weak[7] = weak[8] = 0;
  weak[9] = 1;
  EXPECT_FALSE(openPrivateKey(weak, passphrase, &opened, &error));
}

TEST_F(KeyFileTest, SealRejectsWeakIterationCount) {
  QByteArray out;
  EXPECT_FALSE(sealPrivateKey(pkcs8, passphrase, &out, &error, 1000));
}

// UT-05：同一把私钥、同一个口令连续封装 100 次，每个文件的盐和 nonce 都不同
TEST_F(KeyFileTest, HundredSealsUseFreshSaltAndNonce) {
  QSet<QByteArray> salts, nonces, files;
  for (int i = 0; i < 100; ++i) {
    QByteArray out;
    ASSERT_TRUE(sealPrivateKey(pkcs8, passphrase, &out, &error, kTestIterations));
    salts.insert(out.mid(10, 16));
    nonces.insert(out.mid(26, 12));
    files.insert(out);
  }
  EXPECT_EQ(salts.size(), 100);
  EXPECT_EQ(nonces.size(), 100);
  EXPECT_EQ(files.size(), 100);
}
