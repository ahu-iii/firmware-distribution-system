#include "signer/cert_builder.h"

#include <openssl/ec.h>

#include <QHostAddress>
#include <QRegularExpression>

#include "common/crypto/rand.h"

namespace fwds {

namespace {

const char kOrganization[] = "FWDS";
const int kSerialBytes = 16;

bool setError(QString* error, const QString& what) {
  *error = QStringLiteral("%1：%2").arg(what, lastOpensslError());
  return false;
}

// 设置有效期起止时间。
bool setValidity(X509* cert, const QDateTime& notBefore, const QDateTime& notAfter) {
  return ASN1_TIME_set(X509_getm_notBefore(cert), static_cast<time_t>(notBefore.toSecsSinceEpoch())) &&
         ASN1_TIME_set(X509_getm_notAfter(cert), static_cast<time_t>(notAfter.toSecsSinceEpoch()));
}

// 持有者名称：CN=<commonName>, O=FWDS。
bool setSubject(X509* cert, const QString& commonName) {
  X509_NAME* name = X509_get_subject_name(cert);
  const QByteArray cn = commonName.toUtf8();
  return X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                    reinterpret_cast<const unsigned char*>(cn.constData()),
                                    static_cast<int>(cn.size()), -1, 0) == 1 &&
         X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>(kOrganization), -1, -1,
                                    0) == 1;
}

// 16 字节随机序列号。最高位清零保证是正数，最低位置 1 保证不为零。
bool setRandomSerial(X509* cert) {
  QByteArray bytes = randomBytes(kSerialBytes);
  bytes[0] = static_cast<char>(bytes[0] & 0x7f);
  bytes[kSerialBytes - 1] = static_cast<char>(bytes[kSerialBytes - 1] | 0x01);
  const OsslPtr<BIGNUM> bn(
      BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.constData()), kSerialBytes, nullptr));
  return bn && BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert)) != nullptr;
}

// 给证书加一个扩展。value 用 OpenSSL 配置文件里的写法，例如 "critical,CA:FALSE"。
bool addExtension(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  const OsslPtr<X509_EXTENSION> ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value));
  return ext && X509_add_ext(cert, ext.get(), -1) == 1;
}

OsslPtr<ASN1_INTEGER> serialFromHex(const QString& hex) {
  BIGNUM* raw = nullptr;
  if (BN_hex2bn(&raw, hex.toLatin1().constData()) == 0) return nullptr;
  const OsslPtr<BIGNUM> bn(raw);
  return OsslPtr<ASN1_INTEGER>(BN_to_ASN1_INTEGER(bn.get(), nullptr));
}

}  // namespace

EvpPkeyPtr generateEcP256Key() {
  const OsslPtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) != 1) {
    return nullptr;
  }
  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) != 1) return nullptr;
  return EvpPkeyPtr(key);
}

bool isValidCertName(CertType type, const QString& name) {
  // 正则用 \A … \z 表示“整个字符串从头到尾”。不用 ^ … $：$ 在字符串末尾的换行符之前
  // 也能匹配，"DEV-001\n" 会被当成合法名称写进证书。
  if (type == CertType::Device) {
    static const QRegularExpression deviceId(QStringLiteral("\\A[A-Za-z0-9_-]{1,64}\\z"));
    return deviceId.match(name).hasMatch();
  }
  // QHostAddress 解析时会自动去掉首尾空白，所以带首尾空白或换行的写法要先挡住
  if (name != name.trimmed()) return false;
  QHostAddress address;
  if (address.setAddress(name)) return true;
  static const QRegularExpression host(
      QStringLiteral("\\A(?=.{1,253}\\z)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
                     "(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\\z"));
  return host.match(name).hasMatch();
}

X509Ptr buildRootCert(EVP_PKEY* caKey, const QString& commonName, const QDateTime& notBefore,
                      const QDateTime& notAfter, QString* error) {
  X509Ptr cert(X509_new());
  if (!cert || X509_set_version(cert.get(), X509_VERSION_3) != 1 ||
      !setRandomSerial(cert.get()) || !setValidity(cert.get(), notBefore, notAfter) ||
      !setSubject(cert.get(), commonName) ||
      // 自签名：签发者就是自己
      X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get())) != 1 ||
      X509_set_pubkey(cert.get(), caKey) != 1) {
    setError(error, QStringLiteral("填写根证书字段失败"));
    return nullptr;
  }
  if (!addExtension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0") ||
      !addExtension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign") ||
      !addExtension(cert.get(), cert.get(), NID_subject_key_identifier, "hash")) {
    setError(error, QStringLiteral("添加根证书扩展失败"));
    return nullptr;
  }
  // ECDSA + SHA-256
  if (X509_sign(cert.get(), caKey, EVP_sha256()) <= 0) {
    setError(error, QStringLiteral("根证书签名失败"));
    return nullptr;
  }
  return cert;
}

X509Ptr buildLeafCert(X509* caCert, EVP_PKEY* caKey, EVP_PKEY* leafKey, CertType type,
                      const QString& name, const QDateTime& notBefore, const QDateTime& notAfter,
                      QString* error) {
  if (!isValidCertName(type, name)) {
    *error = QStringLiteral("证书名称不合法：%1").arg(name);
    return nullptr;
  }
  X509Ptr cert(X509_new());
  if (!cert || X509_set_version(cert.get(), X509_VERSION_3) != 1 ||
      !setRandomSerial(cert.get()) || !setValidity(cert.get(), notBefore, notAfter) ||
      !setSubject(cert.get(), name) ||
      X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert)) != 1 ||
      X509_set_pubkey(cert.get(), leafKey) != 1) {
    setError(error, QStringLiteral("填写证书字段失败"));
    return nullptr;
  }

  const char* usage = type == CertType::Server ? "serverAuth" : "clientAuth";
  if (!addExtension(cert.get(), caCert, NID_basic_constraints, "critical,CA:FALSE") ||
      !addExtension(cert.get(), caCert, NID_key_usage, "critical,digitalSignature") ||
      !addExtension(cert.get(), caCert, NID_ext_key_usage, usage) ||
      !addExtension(cert.get(), caCert, NID_subject_key_identifier, "hash") ||
      !addExtension(cert.get(), caCert, NID_authority_key_identifier, "keyid:always")) {
    setError(error, QStringLiteral("添加证书扩展失败"));
    return nullptr;
  }
  if (type == CertType::Server) {
    // 服务端名称放进“使用者可选名称”：IP 和主机名是两种不同的条目
    QHostAddress address;
    const QByteArray san = (address.setAddress(name) ? "IP:" : "DNS:") + name.toLatin1();
    if (!addExtension(cert.get(), caCert, NID_subject_alt_name, san.constData())) {
      setError(error, QStringLiteral("添加使用者可选名称失败"));
      return nullptr;
    }
  }

  if (X509_sign(cert.get(), caKey, EVP_sha256()) <= 0) {
    setError(error, QStringLiteral("证书签名失败"));
    return nullptr;
  }
  return cert;
}

X509CrlPtr buildCrl(X509* caCert, EVP_PKEY* caKey, const QList<RevokedEntry>& revoked,
                    qint64 number, const QDateTime& thisUpdate, const QDateTime& nextUpdate,
                    QString* error) {
  X509CrlPtr crl(X509_CRL_new());
  const OsslPtr<ASN1_TIME> last(ASN1_TIME_set(nullptr, static_cast<time_t>(thisUpdate.toSecsSinceEpoch())));
  const OsslPtr<ASN1_TIME> next(ASN1_TIME_set(nullptr, static_cast<time_t>(nextUpdate.toSecsSinceEpoch())));
  if (!crl || !last || !next || X509_CRL_set_version(crl.get(), X509_CRL_VERSION_2) != 1 ||
      X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(caCert)) != 1 ||
      X509_CRL_set1_lastUpdate(crl.get(), last.get()) != 1 ||
      X509_CRL_set1_nextUpdate(crl.get(), next.get()) != 1) {
    setError(error, QStringLiteral("填写 CRL 字段失败"));
    return nullptr;
  }

  for (const RevokedEntry& entry : revoked) {
    OsslPtr<X509_REVOKED> item(X509_REVOKED_new());
    const OsslPtr<ASN1_INTEGER> serial = serialFromHex(entry.serialHex);
    const OsslPtr<ASN1_TIME> when(
        ASN1_TIME_set(nullptr, static_cast<time_t>(entry.revokedAt.toSecsSinceEpoch())));
    if (!item || !serial || !when || X509_REVOKED_set_serialNumber(item.get(), serial.get()) != 1 ||
        X509_REVOKED_set_revocationDate(item.get(), when.get()) != 1 ||
        X509_CRL_add0_revoked(crl.get(), item.get()) != 1) {
      setError(error, QStringLiteral("添加吊销条目失败"));
      return nullptr;
    }
    item.release();  // add0 成功后条目归 CRL 所有
  }
  X509_CRL_sort(crl.get());

  // CRL 序号扩展：校验方用它拒绝比当前更旧的 CRL
  const OsslPtr<ASN1_INTEGER> crlNumber(ASN1_INTEGER_new());
  if (!crlNumber || ASN1_INTEGER_set_int64(crlNumber.get(), number) != 1 ||
      X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, crlNumber.get(), 0, 0) != 1) {
    setError(error, QStringLiteral("添加 CRL 序号失败"));
    return nullptr;
  }

  if (X509_CRL_sign(crl.get(), caKey, EVP_sha256()) <= 0) {
    setError(error, QStringLiteral("CRL 签名失败"));
    return nullptr;
  }
  return crl;
}

}  // namespace fwds
