// 测试用的证书体系：每次运行测试时在内存里现建一个 CA，现签服务端和设备证书。
// 仓库里因此不需要存放任何测试私钥（检查项 1-3）。
#pragma once

#include <QDateTime>
#include <memory>

#include "common/crypto/secure_buffer.h"
#include "common/crypto/x509_util.h"
#include "common/security/tls_channel.h"
#include "signer/cert_builder.h"

namespace fwds_test {

// 一张证书和它的私钥。
struct Identity {
  QByteArray certPem;
  QByteArray certDer;
  QString serialHex;
  fwds::SecureBuffer keyPkcs8;
};

class TestPki {
 public:
  explicit TestPki(const QString& caName = QStringLiteral("FWDS Test CA")) {
    caKey_ = fwds::generateEcP256Key();
    QString error;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    caCert_ = fwds::buildRootCert(caKey_.get(), caName, now.addSecs(-300), now.addDays(30), &error);
  }

  QByteArray caPem() const { return fwds::certToPem(caCert_.get()); }

  // 签发一张证书。默认有效期为“5 分钟前 ~ 30 天后”，测试过期证书时自己给时间。
  Identity issue(fwds::CertType type, const QString& name, QDateTime notBefore = QDateTime(),
                 QDateTime notAfter = QDateTime()) const {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (!notBefore.isValid()) notBefore = now.addSecs(-300);
    if (!notAfter.isValid()) notAfter = now.addDays(30);
    const fwds::EvpPkeyPtr key = fwds::generateEcP256Key();
    QString error;
    const fwds::X509Ptr cert = fwds::buildLeafCert(caCert_.get(), caKey_.get(), key.get(), type,
                                                   name, notBefore, notAfter, &error);
    Identity id;
    if (!cert) return id;
    id.certPem = fwds::certToPem(cert.get());
    id.certDer = fwds::certToDer(cert.get());
    id.serialHex = fwds::certSerialHex(cert.get());
    fwds::privateKeyToPkcs8(key.get(), &id.keyPkcs8);
    return id;
  }

  // 生成一份 CRL。序号每次自动加 1；validSeconds 为负数可以得到已过期的 CRL。
  QByteArray crl(const QStringList& revokedSerials = {}, qint64 validSeconds = 24 * 3600) {
    return crlWithNumber(++crlNumber_, revokedSerials, validSeconds);
  }

  QByteArray crlWithNumber(qint64 number, const QStringList& revokedSerials = {},
                           qint64 validSeconds = 24 * 3600) const {
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QList<fwds::RevokedEntry> revoked;
    for (const QString& serial : revokedSerials) revoked.append({serial, now.addSecs(-60)});
    QString error;
    // 签发时间取一小时前，这样 validSeconds 为负时“下次更新时间”仍晚于签发时间
    const fwds::X509CrlPtr crl = fwds::buildCrl(caCert_.get(), caKey_.get(), revoked, number,
                                                now.addSecs(-3600), now.addSecs(validSeconds), &error);
    return crl ? fwds::crlToPem(crl.get()) : QByteArray();
  }

  // 用某张证书建一个 TLS 信道对象。expectedServerName 只有客户端一侧会用到。
  std::unique_ptr<fwds::TlsChannelSecurity> security(
      const Identity& id, const QString& expectedServerName = QStringLiteral("127.0.0.1")) {
    auto s = std::make_unique<fwds::TlsChannelSecurity>();
    QString error;
    if (!s->load(caPem(), crl(), id.certPem, id.keyPkcs8, &error)) return nullptr;
    s->setExpectedServerName(expectedServerName);
    return s;
  }

 private:
  fwds::EvpPkeyPtr caKey_;
  fwds::X509Ptr caCert_;
  qint64 crlNumber_ = 0;
};

// 各测试共用的一套证书：CA、127.0.0.1 的服务端证书、DEV-001 的设备证书。
struct SharedPki {
  TestPki pki;
  Identity server = pki.issue(fwds::CertType::Server, QStringLiteral("127.0.0.1"));
  Identity dev001 = pki.issue(fwds::CertType::Device, QStringLiteral("DEV-001"));
  Identity dev002 = pki.issue(fwds::CertType::Device, QStringLiteral("DEV-002"));
};

inline SharedPki& sharedPki() {
  static SharedPki instance;
  return instance;
}

}  // namespace fwds_test
