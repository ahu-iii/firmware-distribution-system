// AES-256-GCM（设计 10.3 节）：带认证的加密，密文、标签或关联数据被改动时解密失败。
// 用于封装私钥文件（key_file）。只调用 OpenSSL EVP 接口，不自己实现算法。
#pragma once

#include <QByteArray>

#include "common/crypto/secure_buffer.h"

namespace fwds {

inline constexpr int kGcmKeySize = 32;    // AES-256
inline constexpr int kGcmNonceSize = 12;  // GCM 推荐的 96 位 nonce
inline constexpr int kGcmTagSize = 16;    // 完整的 128 位认证标签，不截短

// 加密。key 必须 32 字节，nonce 必须 12 字节且在同一把 key 下不能重复。
// aad 是“只认证不加密”的关联数据（例如文件头）。成功时输出等长密文和 16 字节标签。
bool aesGcmEncrypt(const SecureBuffer& key, const QByteArray& nonce, const QByteArray& aad,
                   const SecureBuffer& plaintext, QByteArray* ciphertext, QByteArray* tag);

// 解密并校验标签。任何一处被改动都返回 false，并且 plaintext 被清空，不输出任何明文。
bool aesGcmDecrypt(const SecureBuffer& key, const QByteArray& nonce, const QByteArray& aad,
                   const QByteArray& ciphertext, const QByteArray& tag, SecureBuffer* plaintext);

}  // namespace fwds
