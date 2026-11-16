// TlsChannelSecurity：ChannelSecurity 的 TLS 实现（设计第 3 节 TlsContext，第 10 章）。
// 服务端和设备客户端用同一个类，区别只在加载的证书不同、校验对端时的角色不同。
//   prepare()    握手前把 socket 配成：只用 TLS 1.3、只用 TLS_AES_256_GCM_SHA384、X25519 密钥交换、
//                双向认证、只信任自建 CA、禁用会话复用（协议第 2 节）
//   verifyPeer() 握手后复查协议版本和套件，再用 CertVerifier 对对端证书做完整校验
#pragma once

#include <QDateTime>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslKey>

#include "common/config.h"
#include "common/crypto/secure_buffer.h"
#include "common/net/channel_security.h"
#include "common/security/cert_verifier.h"

namespace fwds {

inline constexpr char kTlsCipherSuite[] = "TLS_AES_256_GCM_SHA384";

class TlsChannelSecurity : public ChannelSecurity {
 public:
  explicit TlsChannelSecurity(const CertLimits& limits = CertLimits());

  // 客户端必须设置：期望的服务端名称（配置里的 server_host），用来和服务端证书比对。
  void setExpectedServerName(const QString& name) { expectedServerName_ = name; }

  // 从配置给出的文件加载 CA 证书、CRL、本端证书和封装的私钥。任何一项有问题都返回 false。
  // 加载之后每次握手前会检查 CRL 文件是否被更新，更新了就重新加载。
  bool loadFiles(const TlsConfig& config, const SecureBuffer& keyPassphrase, QString* error);

  // 从内存加载（单元测试用，也是 loadFiles 的后半段）。keyPkcs8 是私钥的 PKCS#8 DER 明文。
  bool load(const QByteArray& caPem, const QByteArray& crlPem, const QByteArray& certPem,
            const SecureBuffer& keyPkcs8, QString* error);

  // 换用新的 CRL（维护员导入新 CRL 时）。新 CRL 不合格时保留原来的并返回 false。
  bool reloadCrl(const QByteArray& crlPem, QString* error);

  // 本端证书的身份和到期时间（客户端启动时核对设备 ID；界面做到期提醒）。
  const PeerIdentity& localIdentity() const { return localIdentity_; }
  QDateTime localCertNotAfter() const { return localNotAfter_; }

  void prepare(QSslSocket* socket, bool serverSide) override;
  QString verifyPeer(const QSslSocket* socket, bool serverSide, PeerIdentity* peer) override;

 private:
  void reloadCrlFileIfChanged();

  CertVerifier verifier_;
  QSslCertificate caCert_;
  QSslCertificate localCert_;
  QSslKey localKey_;
  QSslCipher cipher_;
  PeerIdentity localIdentity_;
  QDateTime localNotAfter_;
  QString expectedServerName_;
  QString crlFile_;         // 为空表示不是从文件加载的
  QDateTime crlFileMtime_;  // 上次加载时 CRL 文件的修改时间
};

}  // namespace fwds
