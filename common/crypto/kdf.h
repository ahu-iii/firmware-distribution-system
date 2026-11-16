// 口令慢派生（设计 11.2、11.3 节）：PBKDF2-HMAC-SHA256。
// 口令不能直接当密钥用，也不能只做一次哈希；迭代几十万次让暴力猜口令的代价成倍增加。
#pragma once

#include <QByteArray>

#include "common/crypto/secure_buffer.h"

namespace fwds {

inline constexpr int kKdfSaltSize = 16;
inline constexpr int kKdfDefaultIterations = 600000;  // 设计 11.2 节

// 由口令、盐和迭代次数派生 keySize 字节的密钥。参数非法或 OpenSSL 报错时返回 false。
bool pbkdf2Sha256(const SecureBuffer& passphrase, const QByteArray& salt, int iterations,
                  int keySize, SecureBuffer* key);

}  // namespace fwds
