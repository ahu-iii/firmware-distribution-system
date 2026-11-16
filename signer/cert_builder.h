// 证书和 CRL 的生成（设计 10.1 节）。只有离线签发工具用得到，所以放在 signer/，
// 不编进服务端和客户端程序。全部通过 OpenSSL 的 X.509 接口完成。
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>

#include "common/crypto/openssl_util.h"

namespace fwds {

enum class CertType {
  Server,  // 服务端证书：名称是主机名或 IP，用途 serverAuth
  Device,  // 设备证书：名称是设备 ID，用途 clientAuth
};

// 一条吊销记录。
struct RevokedEntry {
  QString serialHex;
  QDateTime revokedAt;  // UTC
};

// 生成一对 ECDSA P-256 密钥（设计 11.3 节密钥清单）。失败返回空指针。
EvpPkeyPtr generateEcP256Key();

// 名称是否合法。设备 ID：字母、数字、'-'、'_'，1 ~ 64 个字符；
// 服务端名称：IP 地址，或由字母、数字、'-'、'.' 组成的主机名。
// 名称会被写进证书扩展，这里先把字符集限制死。
bool isValidCertName(CertType type, const QString& name);

// 自签名根证书。扩展：CA:TRUE（不允许再签下级 CA）、密钥用途仅限签证书和签 CRL。
X509Ptr buildRootCert(EVP_PKEY* caKey, const QString& commonName, const QDateTime& notBefore,
                      const QDateTime& notAfter, QString* error);

// 由 CA 签发的叶子证书。序列号为 16 字节随机数。
// 扩展：CA:FALSE、密钥用途仅限数字签名、按类型限定 serverAuth 或 clientAuth；
// 服务端证书另带“使用者可选名称”（IP 或 DNS），客户端按它核对服务端名称。
X509Ptr buildLeafCert(X509* caCert, EVP_PKEY* caKey, EVP_PKEY* leafKey, CertType type,
                      const QString& name, const QDateTime& notBefore, const QDateTime& notAfter,
                      QString* error);

// 由 CA 签名的 CRL。number 是 CRL 序号，每次生成加 1；nextUpdate 之后这份 CRL 视为过期。
X509CrlPtr buildCrl(X509* caCert, EVP_PKEY* caKey, const QList<RevokedEntry>& revoked,
                    qint64 number, const QDateTime& thisUpdate, const QDateTime& nextUpdate,
                    QString* error);

}  // namespace fwds
