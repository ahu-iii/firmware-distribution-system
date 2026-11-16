// RSA-PSS 签名与验签（设计第 3 节 crypto::rsa_pss、第 12.1 节）。
// 固件签名密钥 FSK 是 RSA-3072；签名参数固定为：
//   摘要 SHA-256、掩码生成函数 MGF1-SHA256、盐长 32 字节（等于摘要长度）。
// PSS 每次签名都用 RAND_bytes 生成新的盐，所以同一份数据签两次得到的签名不同，但都能验过。
// 只调用 OpenSSL EVP 接口，不自己实现算法。
#pragma once

#include <QByteArray>
#include <QString>

#include "common/crypto/openssl_util.h"

namespace fwds {

inline constexpr int kFskKeyBits = 3072;        // FSK 的模长
inline constexpr int kFskSignatureSize = 384;   // RSA-3072 的签名长度 = 3072 / 8 字节

// 这把密钥是不是 RSA-3072。签名和验签都先做这项检查：
// 换成别的算法或更短的密钥（例如攻击者自己生成的 RSA-1024）一律不接受。
bool isRsa3072(EVP_PKEY* key);

// 用私钥对 message 签名。成功时 signature 为 384 字节。
bool rsaPssSign(EVP_PKEY* privateKey, const QByteArray& message, QByteArray* signature,
                QString* error);

// 用公钥验签。只有“签名确实是这把密钥对这份数据签的”才返回 true；
// 密钥不是 RSA-3072、签名长度不对、数据或签名被改过，都返回 false。
bool rsaPssVerify(EVP_PKEY* publicKey, const QByteArray& message, const QByteArray& signature);

// ---- 公钥的编解码（公钥是公开的，用普通 PEM 保存）----
EvpPkeyPtr publicKeyFromPem(const QByteArray& pem);  // 解析失败返回空指针
QByteArray publicKeyToPem(EVP_PKEY* key);            // 只导出公钥部分，传入私钥对象也不会带出私钥

// 公钥指纹：公钥 DER 编码的 SHA-256，小写十六进制。用来人工核对“设备里装的是不是这把公钥”。
QString publicKeyFingerprintSha256(EVP_PKEY* key);

}  // namespace fwds
