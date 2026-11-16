#include "common/security/cert_verifier.h"

#include <QHostAddress>

#include "common/crypto/x509_util.h"

namespace fwds {

namespace {

const qint64 kSecondsPerDay = 24 * 3600;
const qint64 kClockSkewSeconds = 300;  // 允许签发主机的时钟比本机快 5 分钟

CertCheck fail(CertError error, const QString& detail) { return CertCheck{error, detail}; }

// 证书有效期总时长是否超过上限。
bool validityTooLong(X509* cert, int maxDays) {
  const QDateTime notBefore = certNotBefore(cert);
  const QDateTime notAfter = certNotAfter(cert);
  if (!notBefore.isValid() || !notAfter.isValid()) return true;
  return notBefore.secsTo(notAfter) > static_cast<qint64>(maxDays) * kSecondsPerDay;
}

// 把 OpenSSL 的校验错误码归到我们关心的几类里（设计 10.2 节的四项）。
CertError classify(int opensslError) {
  switch (opensslError) {
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CERT_NOT_YET_VALID:
      return CertError::NotInValidity;
    case X509_V_ERR_CERT_REVOKED:
      return CertError::Revoked;
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
      return CertError::NameMismatch;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
      return CertError::CrlUnusable;
    case X509_V_ERR_INVALID_PURPOSE:
      return CertError::WrongPurpose;
    default:
      return CertError::UntrustedChain;
  }
}

}  // namespace

CertVerifier::CertVerifier(const CertLimits& limits) : limits_(limits) {}

bool CertVerifier::loadCa(const QByteArray& caPem, QString* error) {
  X509Ptr ca = certFromPem(caPem);
  if (!ca) {
    *error = QStringLiteral("CA 证书无法解析");
    return false;
  }
  // 根证书必须是自签名的 CA：签发者就是自己，并且能用自己的公钥验过签名
  if (X509_check_issued(ca.get(), ca.get()) != X509_V_OK ||
      X509_verify(ca.get(), X509_get0_pubkey(ca.get())) != 1 || X509_check_ca(ca.get()) < 1) {
    *error = QStringLiteral("CA 证书不是自签名的 CA 证书");
    return false;
  }
  const QDateTime now = QDateTime::currentDateTimeUtc();
  if (now < certNotBefore(ca.get()) || now > certNotAfter(ca.get())) {
    *error = QStringLiteral("CA 证书不在有效期内");
    return false;
  }
  if (validityTooLong(ca.get(), limits_.maxCaDays)) {
    *error = QStringLiteral("CA 证书有效期超过上限 %1 天").arg(limits_.maxCaDays);
    return false;
  }

  ca_ = std::move(ca);
  // 换了 CA，原来的 CRL 不再适用
  crl_.reset();
  crlNumber_ = -1;
  crlNextUpdate_ = QDateTime();
  return rebuildStore(error);
}

bool CertVerifier::loadCrl(const QByteArray& crlPem, QString* error) {
  if (!ca_) {
    *error = QStringLiteral("尚未加载 CA 证书");
    return false;
  }
  X509CrlPtr crl = crlFromPem(crlPem);
  if (!crl) {
    *error = QStringLiteral("CRL 无法解析");
    return false;
  }
  // 签发者必须是我们的 CA，并且签名能用 CA 公钥验过：被改过一个字节的 CRL 在这里被拒
  if (X509_NAME_cmp(X509_CRL_get_issuer(crl.get()), X509_get_subject_name(ca_.get())) != 0 ||
      X509_CRL_verify(crl.get(), X509_get0_pubkey(ca_.get())) != 1) {
    *error = QStringLiteral("CRL 不是由自建 CA 签发的，或签名无效");
    return false;
  }
  const QDateTime now = QDateTime::currentDateTimeUtc();
  const QDateTime lastUpdate = asn1TimeToUtc(X509_CRL_get0_lastUpdate(crl.get()));
  const QDateTime nextUpdate = asn1TimeToUtc(X509_CRL_get0_nextUpdate(crl.get()));
  if (!lastUpdate.isValid() || lastUpdate > now.addSecs(kClockSkewSeconds)) {
    *error = QStringLiteral("CRL 的签发时间在未来");
    return false;
  }
  if (!nextUpdate.isValid() || nextUpdate <= now) {
    *error = QStringLiteral("CRL 已过期，需要签发工具重新生成");
    return false;
  }
  const qint64 number = crlNumber(crl.get());
  if (number < 0 || number < crlNumber_) {
    *error = QStringLiteral("CRL 序号比当前使用的旧，拒绝回退");
    return false;
  }

  crl_ = std::move(crl);
  crlNumber_ = number;
  crlNextUpdate_ = nextUpdate;
  return rebuildStore(error);
}

bool CertVerifier::rebuildStore(QString* error) {
  OsslPtr<X509_STORE> store(X509_STORE_new());
  if (!store || X509_STORE_add_cert(store.get(), ca_.get()) != 1) {
    *error = QStringLiteral("建立信任库失败：%1").arg(lastOpensslError());
    return false;
  }
  if (crl_ && X509_STORE_add_crl(store.get(), crl_.get()) != 1) {
    *error = QStringLiteral("CRL 加入信任库失败：%1").arg(lastOpensslError());
    return false;
  }
  // 强制查吊销：信任库里没有可用的 CRL 时校验直接失败，而不是当作“没被吊销”
  if (X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK) != 1) {
    *error = QStringLiteral("设置吊销检查失败");
    return false;
  }
  store_ = std::move(store);
  return true;
}

CertCheck CertVerifier::verify(const QByteArray& certDer, PeerRole role,
                               const QString& expectedName, PeerIdentity* peer) const {
  const X509Ptr cert = certFromDer(certDer);
  if (!cert) return fail(CertError::Malformed, QStringLiteral("证书无法解析"));
  if (!store_ || !crl_) return fail(CertError::NotReady, QStringLiteral("CA 或 CRL 尚未加载"));

  const OsslPtr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
  if (!ctx || X509_STORE_CTX_init(ctx.get(), store_.get(), cert.get(), nullptr) != 1) {
    return fail(CertError::UntrustedChain, lastOpensslError());
  }
  X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx.get());

  // 用途：服务端证书必须带 serverAuth，设备证书必须带 clientAuth。
  // 两种证书出自同一个 CA，这一项挡住“拿设备证书冒充服务端”。
  const int purpose =
      role == PeerRole::Server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
  if (X509_VERIFY_PARAM_set_purpose(param, purpose) != 1) {
    return fail(CertError::WrongPurpose, lastOpensslError());
  }

  // 名称：服务端证书按主机名或 IP 比对证书里的“使用者可选名称”
  if (role == PeerRole::Server) {
    if (expectedName.isEmpty()) {
      return fail(CertError::NameMismatch, QStringLiteral("没有给出期望的服务端名称"));
    }
    const QByteArray name = expectedName.toUtf8();
    QHostAddress address;
    const int ok = address.setAddress(expectedName)
                       ? X509_VERIFY_PARAM_set1_ip_asc(param, name.constData())
                       : X509_VERIFY_PARAM_set1_host(param, name.constData(), 0);
    if (ok != 1) return fail(CertError::NameMismatch, QStringLiteral("期望的服务端名称不合法"));
  }

  // 一次调用完成：链（到自建 CA）、签名、有效期、用途、名称、CRL 签名与吊销状态
  if (X509_verify_cert(ctx.get()) != 1) {
    const int code = X509_STORE_CTX_get_error(ctx.get());
    return fail(classify(code), QString::fromLatin1(X509_verify_cert_error_string(code)));
  }

  if (validityTooLong(cert.get(), limits_.maxLeafDays)) {
    return fail(CertError::ValidityTooLong,
                QStringLiteral("证书有效期超过上限 %1 天").arg(limits_.maxLeafDays));
  }

  const QString commonName = certCommonName(cert.get());
  if (role == PeerRole::Device) {
    // 设备证书用 CN 承载设备 ID
    if (commonName.isEmpty()) {
      return fail(CertError::NameMismatch, QStringLiteral("设备证书没有名称"));
    }
    if (!expectedName.isEmpty() && commonName != expectedName) {
      return fail(CertError::NameMismatch, QStringLiteral("设备证书名称与期望的设备 ID 不符"));
    }
  }

  if (peer) {
    peer->name = commonName;
    peer->serialHex = certSerialHex(cert.get());
    peer->fingerprint = certFingerprintSha256(cert.get());
  }
  return CertCheck();
}

}  // namespace fwds
