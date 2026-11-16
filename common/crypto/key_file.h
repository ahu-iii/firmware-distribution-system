// 私钥文件封装（设计 11.3 节，检查项 1-3、1-4）。
// 私钥先编码成 PKCS#8 DER，再用 AES-256-GCM 加密；加密密钥由口令经 PBKDF2 派生。
// 不用 OpenSSL 自带的 PEM 加密，因为它默认是没有认证的 CBC 模式。
//
// 文件布局（多字节整数为大端）：
//   偏移  长度  内容
//   0     4     魔数 "FWKY"
//   4     1     格式版本，当前为 1
//   5     1     派生函数标识，1 = PBKDF2-HMAC-SHA256
//   6     4     迭代次数
//   10    16    盐（每次写文件新生成）
//   26    12    nonce（每次写文件新生成）
//   38    4     密文长度 N
//   42    N     密文
//   42+N  16    GCM 认证标签
// 前 42 字节（文件头）作为关联数据参与认证，所以改动文件里任何一个字节都会解密失败。
#pragma once

#include <QByteArray>
#include <QString>

#include "common/crypto/kdf.h"
#include "common/crypto/secure_buffer.h"

namespace fwds {

inline constexpr int kKeyFileHeaderSize = 42;
inline constexpr int kKeyFileMinIterations = 100000;     // 低于这个值的文件拒绝打开
inline constexpr int kKeyFileMaxIterations = 10000000;   // 防止恶意文件让程序算上几个小时
inline constexpr int kKeyFileMaxCiphertext = 16 * 1024;  // 私钥只有几百字节，超过即视为损坏

// 封装：pkcs8 为私钥的 PKCS#8 DER 明文。盐和 nonce 在函数内用 RAND_bytes 生成。
// 成功返回 true，sealed 为完整的文件内容。
bool sealPrivateKey(const SecureBuffer& pkcs8, const SecureBuffer& passphrase, QByteArray* sealed,
                    QString* error, int iterations = kKdfDefaultIterations);

// 解封：口令错误、文件被改动、格式不对都返回 false，pkcs8 为空。
// 错误信息不区分“口令错”和“文件被改”，两种情况在密码学上无法区分，也不应该给攻击者提示。
bool openPrivateKey(const QByteArray& sealed, const SecureBuffer& passphrase, SecureBuffer* pkcs8,
                    QString* error);

}  // namespace fwds
