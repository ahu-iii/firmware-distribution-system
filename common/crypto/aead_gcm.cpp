#include "common/crypto/aead_gcm.h"

#include "common/crypto/openssl_util.h"

namespace fwds {

namespace {

const unsigned char* bytes(const QByteArray& a) {
  return reinterpret_cast<const unsigned char*>(a.constData());
}

}  // namespace

bool aesGcmEncrypt(const SecureBuffer& key, const QByteArray& nonce, const QByteArray& aad,
                   const SecureBuffer& plaintext, QByteArray* ciphertext, QByteArray* tag) {
  if (key.size() != kGcmKeySize || nonce.size() != kGcmNonceSize) return false;

  OsslPtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) return false;
  // 先选算法，再设 nonce 长度，最后给 key 和 nonce
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, kGcmNonceSize, nullptr) != 1) return false;
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), bytes(nonce)) != 1) return false;

  int len = 0;
  // 关联数据：输出缓冲区传空指针表示只参与认证
  if (!aad.isEmpty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &len, bytes(aad), static_cast<int>(aad.size())) != 1) {
    return false;
  }

  // GCM 是流式模式，密文和明文等长
  ciphertext->resize(plaintext.size());
  auto* out = reinterpret_cast<unsigned char*>(ciphertext->data());
  if (EVP_EncryptUpdate(ctx.get(), out, &len, plaintext.data(), plaintext.size()) != 1) return false;
  int total = len;
  if (EVP_EncryptFinal_ex(ctx.get(), out + total, &len) != 1) return false;
  total += len;
  if (total != plaintext.size()) return false;

  tag->resize(kGcmTagSize);
  return EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kGcmTagSize, tag->data()) == 1;
}

bool aesGcmDecrypt(const SecureBuffer& key, const QByteArray& nonce, const QByteArray& aad,
                   const QByteArray& ciphertext, const QByteArray& tag, SecureBuffer* plaintext) {
  plaintext->reset(0);
  if (key.size() != kGcmKeySize || nonce.size() != kGcmNonceSize || tag.size() != kGcmTagSize) {
    return false;
  }

  OsslPtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) return false;
  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, kGcmNonceSize, nullptr) != 1) return false;
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), bytes(nonce)) != 1) return false;

  int len = 0;
  if (!aad.isEmpty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, bytes(aad), static_cast<int>(aad.size())) != 1) {
    return false;
  }

  SecureBuffer out(static_cast<int>(ciphertext.size()));
  if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, bytes(ciphertext),
                        static_cast<int>(ciphertext.size())) != 1) {
    return false;
  }
  int total = len;

  // 把期望的标签交给 OpenSSL，EVP_DecryptFinal_ex 里做常数时间比较。
  // 返回值不是 1 就是认证失败：out 在这里析构并清零，调用方拿不到未经认证的明文。
  QByteArray expected = tag;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kGcmTagSize, expected.data()) != 1) {
    return false;
  }
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) != 1) return false;
  total += len;
  if (total != out.size()) return false;

  *plaintext = std::move(out);
  return true;
}

}  // namespace fwds
