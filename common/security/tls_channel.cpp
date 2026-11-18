#include "common/security/tls_channel.h"

#include <QFile>
#include <QFileInfo>
#include <QSslConfiguration>
#include <QSslEllipticCurve>
#include <QSslSocket>

#include "common/crypto/x509_util.h"
#include "common/log.h"
#include "common/security/key_store.h"

namespace fwds {

namespace {

bool readFile(const QString& path, const QString& what, QByteArray* content, QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取%1：%2").arg(what, path);
    return false;
  }
  *content = file.readAll();
  return true;
}

// PKCS#8 DER → PEM（"PRIVATE KEY" 块）。只是换一种编码，内容仍是私钥明文。
QByteArray pkcs8ToPem(const SecureBuffer& pkcs8) {
  // fromRawData 不拷贝数据，只是让 toBase64() 能直接读 SecureBuffer 里的内容
  const QByteArray der =
      QByteArray::fromRawData(reinterpret_cast<const char*>(pkcs8.data()), pkcs8.size());
  return "-----BEGIN PRIVATE KEY-----\n" + der.toBase64() + "\n-----END PRIVATE KEY-----\n";
}

}  // namespace

TlsChannelSecurity::TlsChannelSecurity(const CertLimits& limits) : verifier_(limits) {}

bool TlsChannelSecurity::loadFiles(const TlsConfig& config, const SecureBuffer& keyPassphrase,
                                   QString* error) {
  QByteArray caPem, crlPem, certPem;
  if (!readFile(config.caFile, QStringLiteral(" CA 证书"), &caPem, error) ||
      !readFile(config.crlFile, QStringLiteral(" CRL"), &crlPem, error) ||
      !readFile(config.certFile, QStringLiteral("本端证书"), &certPem, error)) {
    return false;
  }
  SecureBuffer keyPkcs8;
  if (!loadSealedKeyFile(config.keyFile, keyPassphrase, &keyPkcs8, error)) return false;
  if (!load(caPem, crlPem, certPem, keyPkcs8, error)) return false;

  crlFile_ = config.crlFile;
  crlFileMtime_ = QFileInfo(crlFile_).lastModified();
  return true;
}

bool TlsChannelSecurity::load(const QByteArray& caPem, const QByteArray& crlPem,
                              const QByteArray& certPem, const SecureBuffer& keyPkcs8,
                              QString* error) {
  // Qt 在 Windows 上还带 Schannel、在 macOS 上还带 Secure Transport 两个系统 TLS 后端，
  // 找不到 OpenSSL 运行库时会悄悄换成它们。它们不支持这里要求的“只开一个套件、只用 X25519”，
  // 所以只认 OpenSSL 后端，而且必须是 3.x，否则不启动网络（不降级凑合）。
  const QString backend = QSslSocket::activeBackend();
  if (backend != QStringLiteral("openssl") || !QSslSocket::supportsSsl()) {
    *error = QStringLiteral("Qt 没有加载 OpenSSL 运行库（当前 TLS 后端：%1），无法建立 TLS")
                 .arg(backend.isEmpty() ? QStringLiteral("无") : backend);
    return false;
  }
  if (QSslSocket::sslLibraryVersionNumber() < 0x30000000L) {
    *error = QStringLiteral("Qt 加载的 OpenSSL 版本过低：%1，需要 3.x")
                 .arg(QSslSocket::sslLibraryVersionString());
    return false;
  }
  if (!verifier_.loadCa(caPem, error) || !verifier_.loadCrl(crlPem, error)) return false;

  // 本端证书和私钥：先用 OpenSSL 确认两者是一对，证书在有效期内
  const X509Ptr cert = certFromPem(certPem);
  const EvpPkeyPtr key = privateKeyFromPkcs8(keyPkcs8);
  if (!cert || !key) {
    *error = QStringLiteral("本端证书或私钥无法解析");
    return false;
  }
  if (X509_check_private_key(cert.get(), key.get()) != 1) {
    *error = QStringLiteral("本端证书与私钥不匹配");
    return false;
  }
  const QDateTime now = QDateTime::currentDateTimeUtc();
  if (now < certNotBefore(cert.get()) || now > certNotAfter(cert.get())) {
    *error = QStringLiteral("本端证书不在有效期内，需要重新签发");
    return false;
  }

  // 转成 Qt 的对象交给 QSslSocket 使用。QSslKey 只接受 PEM 或 DER 文本，
  // 所以把 PKCS#8 明文临时编码成 PEM，交给 Qt 之后立刻把这份临时文本清零。
  caCert_ = QSslCertificate(caPem, QSsl::Pem);
  localCert_ = QSslCertificate(certPem, QSsl::Pem);
  QByteArray keyPem = pkcs8ToPem(keyPkcs8);
  localKey_ = QSslKey(keyPem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
  OPENSSL_cleanse(keyPem.data(), static_cast<size_t>(keyPem.size()));
  cipher_ = QSslCipher(QString::fromLatin1(kTlsCipherSuite));
  if (caCert_.isNull() || localCert_.isNull() || localKey_.isNull() || cipher_.isNull()) {
    *error = QStringLiteral("TLS 材料转换失败（证书、私钥或套件 %1 不可用）")
                 .arg(QString::fromLatin1(kTlsCipherSuite));
    return false;
  }

  localIdentity_.name = certCommonName(cert.get());
  localIdentity_.serialHex = certSerialHex(cert.get());
  localIdentity_.fingerprint = certFingerprintSha256(cert.get());
  localNotAfter_ = certNotAfter(cert.get());
  return true;
}

bool TlsChannelSecurity::reloadCrl(const QByteArray& crlPem, QString* error) {
  return verifier_.loadCrl(crlPem, error);
}

void TlsChannelSecurity::reloadCrlFileIfChanged() {
  if (crlFile_.isEmpty()) return;
  const QDateTime mtime = QFileInfo(crlFile_).lastModified();
  if (mtime == crlFileMtime_) return;
  crlFileMtime_ = mtime;

  QByteArray crlPem;
  QString error;
  if (readFile(crlFile_, QStringLiteral(" CRL"), &crlPem, &error) && reloadCrl(crlPem, &error)) {
    qCInfo(lcSecurity) << "CRL reloaded, number" << verifier_.loadedCrlNumber();
  } else {
    // 新文件不合格（签名不对、过期、序号回退）：继续用原来的 CRL，并告警
    qCCritical(lcSecurity).noquote() << "CRL file changed but was rejected:" << error;
  }
}

void TlsChannelSecurity::prepare(QSslSocket* socket, bool serverSide) {
  Q_UNUSED(serverSide);
  QSslConfiguration config = socket->sslConfiguration();

  // 只允许 TLS 1.3，只启用一个带认证加密的套件（检查项 4-3、1-4）
  config.setProtocol(QSsl::TlsV1_3);
  config.setCiphers({cipher_});
  // 密钥交换只用 X25519 临时密钥（前向安全）
  config.setEllipticCurves({QSslEllipticCurve::fromLongName(QStringLiteral("X25519"))});

  // 双向认证：VerifyPeer 表示对端必须出示证书并通过校验，客户端和服务端都这样设。
  // 信任库只放自建 CA，系统证书库里的任何 CA 都不被信任（检查项 4-1）。
  config.setPeerVerifyMode(QSslSocket::VerifyPeer);
  config.setPeerVerifyDepth(1);  // 链上只有“叶子 + 根”，不接受更长的链
  config.setCaCertificates({caCert_});
  config.setLocalCertificate(localCert_);
  config.setPrivateKey(localKey_);

  // 不做会话复用和 0-RTT：每次连接完整握手、重新协商密钥（协议第 2 节）
  config.setSslOption(QSsl::SslOptionDisableSessionTickets, true);
  config.setSslOption(QSsl::SslOptionDisableSessionSharing, true);
  config.setSslOption(QSsl::SslOptionDisableSessionPersistence, true);
  config.setSslOption(QSsl::SslOptionDisableCompression, true);
  socket->setSslConfiguration(config);

  // 握手中发现的证书问题只记日志，绝不调用 ignoreSslErrors()：有任何一项错误握手就失败
  QObject::connect(socket, &QSslSocket::sslErrors, socket, [](const QList<QSslError>& errors) {
    for (const QSslError& e : errors) {
      qCCritical(lcSecurity).noquote() << "TLS certificate error:" << e.errorString();
    }
  });
}

QString TlsChannelSecurity::verifyPeer(const QSslSocket* socket, bool serverSide,
                                       PeerIdentity* peer) {
  // 握手结果复查：即使配置被人改动，也不会在别的协议版本或套件上收发业务数据
  if (socket->sessionProtocol() != QSsl::TlsV1_3) {
    return QStringLiteral("协议版本不是 TLS 1.3");
  }
  if (socket->sessionCipher().name() != QLatin1String(kTlsCipherSuite)) {
    return QStringLiteral("套件不是 %1").arg(QString::fromLatin1(kTlsCipherSuite));
  }

  const QSslCertificate peerCert = socket->peerCertificate();
  if (peerCert.isNull()) return QStringLiteral("对端没有出示证书");

  reloadCrlFileIfChanged();

  // 服务端校验的是设备证书（名称留到登录时和 LOGIN 的设备 ID 比对）；
  // 客户端校验的是服务端证书，名称必须等于配置的服务端主机名或 IP。
  const PeerRole role = serverSide ? PeerRole::Device : PeerRole::Server;
  const QString expectedName = serverSide ? QString() : expectedServerName_;
  const CertCheck check = verifier_.verify(peerCert.toDer(), role, expectedName, peer);
  return check.ok() ? QString() : check.detail;
}

}  // namespace fwds
