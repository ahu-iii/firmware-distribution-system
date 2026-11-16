// 证书、CRL、私钥的编解码和字段读取（设计第 3 节 crypto::x509）。
// 这里只做“读”和“转换格式”；签发在 signer/cert_builder，校验在 common/security/cert_verifier。
#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>

#include "common/crypto/openssl_util.h"
#include "common/crypto/secure_buffer.h"

namespace fwds {

// ---- 证书 ----
X509Ptr certFromPem(const QByteArray& pem);  // 解析失败返回空指针
X509Ptr certFromDer(const QByteArray& der);
QByteArray certToPem(X509* cert);
QByteArray certToDer(X509* cert);

QString certCommonName(X509* cert);          // 持有者名称（Subject 里的 CN）
QString certSerialHex(X509* cert);           // 序列号，大写十六进制
QString certFingerprintSha256(X509* cert);   // 整张证书 DER 的 SHA-256，小写十六进制
QDateTime certNotBefore(X509* cert);         // UTC
QDateTime certNotAfter(X509* cert);          // UTC

// ---- CRL ----
X509CrlPtr crlFromPem(const QByteArray& pem);
QByteArray crlToPem(X509_CRL* crl);
qint64 crlNumber(X509_CRL* crl);             // CRL 序号扩展；没有时返回 -1

// ---- 私钥（PKCS#8 DER 明文只放在 SecureBuffer 里）----
EvpPkeyPtr privateKeyFromPkcs8(const SecureBuffer& pkcs8);
bool privateKeyToPkcs8(EVP_PKEY* key, SecureBuffer* pkcs8);

// ASN.1 时间转 QDateTime（UTC）；无法解析时返回无效时间。
QDateTime asn1TimeToUtc(const ASN1_TIME* time);

}  // namespace fwds
