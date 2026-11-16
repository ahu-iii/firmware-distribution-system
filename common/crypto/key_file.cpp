#include "common/crypto/key_file.h"

#include <QtEndian>

#include "common/crypto/aead_gcm.h"
#include "common/crypto/rand.h"

namespace fwds {

namespace {

const char kMagic[4] = {'F', 'W', 'K', 'Y'};
const quint8 kFormatVersion = 1;
const quint8 kKdfPbkdf2Sha256 = 1;

// 各字段在文件头里的偏移
const int kOffVersion = 4;
const int kOffKdf = 5;
const int kOffIterations = 6;
const int kOffSalt = 10;
const int kOffNonce = kOffSalt + kKdfSaltSize;          // 26
const int kOffCipherLen = kOffNonce + kGcmNonceSize;    // 38

}  // namespace

bool sealPrivateKey(const SecureBuffer& pkcs8, const SecureBuffer& passphrase, QByteArray* sealed,
                    QString* error, int iterations) {
  if (pkcs8.isEmpty() || pkcs8.size() > kKeyFileMaxCiphertext) {
    *error = QStringLiteral("私钥为空或过长");
    return false;
  }
  if (passphrase.isEmpty()) {
    *error = QStringLiteral("口令为空");
    return false;
  }
  if (iterations < kKeyFileMinIterations || iterations > kKeyFileMaxIterations) {
    *error = QStringLiteral("迭代次数超出允许范围");
    return false;
  }

  // 盐和 nonce 每次都新生成，同一把私钥用同一个口令封装两次，得到的文件也完全不同
  const QByteArray salt = randomBytes(kKdfSaltSize);
  const QByteArray nonce = randomBytes(kGcmNonceSize);

  QByteArray header(kKeyFileHeaderSize, '\0');
  memcpy(header.data(), kMagic, sizeof(kMagic));
  header[kOffVersion] = static_cast<char>(kFormatVersion);
  header[kOffKdf] = static_cast<char>(kKdfPbkdf2Sha256);
  qToBigEndian<quint32>(static_cast<quint32>(iterations), header.data() + kOffIterations);
  memcpy(header.data() + kOffSalt, salt.constData(), kKdfSaltSize);
  memcpy(header.data() + kOffNonce, nonce.constData(), kGcmNonceSize);
  qToBigEndian<quint32>(static_cast<quint32>(pkcs8.size()), header.data() + kOffCipherLen);

  SecureBuffer key;
  if (!pbkdf2Sha256(passphrase, salt, iterations, kGcmKeySize, &key)) {
    *error = QStringLiteral("口令派生失败");
    return false;
  }

  QByteArray ciphertext;
  QByteArray tag;
  if (!aesGcmEncrypt(key, nonce, header, pkcs8, &ciphertext, &tag)) {
    *error = QStringLiteral("私钥加密失败");
    return false;
  }
  *sealed = header + ciphertext + tag;
  return true;
}

bool openPrivateKey(const QByteArray& sealed, const SecureBuffer& passphrase, SecureBuffer* pkcs8,
                    QString* error) {
  pkcs8->reset(0);

  // 先把文件头每个字段检查一遍，全部合法才开始做昂贵的口令派生
  if (sealed.size() < kKeyFileHeaderSize + kGcmTagSize ||
      memcmp(sealed.constData(), kMagic, sizeof(kMagic)) != 0) {
    *error = QStringLiteral("不是 FWDS 私钥文件");
    return false;
  }
  if (static_cast<quint8>(sealed[kOffVersion]) != kFormatVersion ||
      static_cast<quint8>(sealed[kOffKdf]) != kKdfPbkdf2Sha256) {
    *error = QStringLiteral("私钥文件的格式版本或派生函数不支持");
    return false;
  }
  const quint32 iterations = qFromBigEndian<quint32>(sealed.constData() + kOffIterations);
  if (iterations < static_cast<quint32>(kKeyFileMinIterations) ||
      iterations > static_cast<quint32>(kKeyFileMaxIterations)) {
    *error = QStringLiteral("私钥文件的迭代次数超出允许范围");
    return false;
  }
  // 长度字段先和上限、再和文件实际长度核对，之后才按它切片
  const quint32 cipherLen = qFromBigEndian<quint32>(sealed.constData() + kOffCipherLen);
  if (cipherLen == 0 || cipherLen > static_cast<quint32>(kKeyFileMaxCiphertext) ||
      static_cast<qsizetype>(cipherLen) != sealed.size() - kKeyFileHeaderSize - kGcmTagSize) {
    *error = QStringLiteral("私钥文件长度与文件头不一致");
    return false;
  }

  const QByteArray header = sealed.left(kKeyFileHeaderSize);
  const QByteArray salt = sealed.mid(kOffSalt, kKdfSaltSize);
  const QByteArray nonce = sealed.mid(kOffNonce, kGcmNonceSize);
  const QByteArray ciphertext = sealed.mid(kKeyFileHeaderSize, static_cast<qsizetype>(cipherLen));
  const QByteArray tag = sealed.right(kGcmTagSize);

  SecureBuffer key;
  if (!pbkdf2Sha256(passphrase, salt, static_cast<int>(iterations), kGcmKeySize, &key) ||
      !aesGcmDecrypt(key, nonce, header, ciphertext, tag, pkcs8)) {
    *error = QStringLiteral("私钥解密失败：口令错误或文件被改动");
    return false;
  }
  return true;
}

}  // namespace fwds
