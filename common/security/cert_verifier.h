// CertVerifier：完整证书校验（设计 10.2 节，检查项 4-2）。
// 一张对端证书要同时通过四项才算合格：
//   签发链    —— 必须由本系统的自建 CA 直接签发（信任库里只有这一张根证书，不加载系统证书库）
//   有效期    —— 当前时间在 notBefore ~ notAfter 之间，且总时长不超过配置的上限
//   持有者名称 —— 服务端证书的名称等于客户端配置的主机名或 IP；设备证书的名称就是设备 ID
//   吊销状态  —— 序列号不在 CRL 里；CRL 本身必须由 CA 签名且没有过期
// 校验不能通过配置关闭。TLS 握手里 OpenSSL 已经查过链和有效期，这里在握手后独立再查一遍，
// 并补上握手不查的吊销状态和有效期上限。
#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>

#include "common/crypto/openssl_util.h"
#include "common/net/channel_security.h"

namespace fwds {

// 被校验的证书属于哪一方。
enum class PeerRole {
  Server,  // 客户端在校验服务端证书
  Device,  // 服务端在校验设备证书
};

enum class CertError {
  None,
  Malformed,        // 不是合法的 X.509 证书
  NotReady,         // CA 或 CRL 还没加载，一律拒绝
  UntrustedChain,   // 不是自建 CA 签发的，或签名不对
  NotInValidity,    // 已过期或尚未生效
  ValidityTooLong,  // 有效期总时长超过上限
  NameMismatch,     // 名称与期望不符
  Revoked,          // 已被吊销
  CrlUnusable,      // CRL 过期或不可用，无法确认吊销状态
  WrongPurpose,     // 证书用途不对（例如拿设备证书冒充服务端）
};

struct CertCheck {
  CertError error = CertError::None;
  QString detail;  // 写日志用的原因说明
  bool ok() const { return error == CertError::None; }
};

// 证书有效期上限（天）。课程规定的上限确定后在配置文件 [tls] 里改，见设计 10.2 节。
struct CertLimits {
  int maxCaDays = 365;
  int maxLeafDays = 90;
};

class CertVerifier {
 public:
  explicit CertVerifier(const CertLimits& limits = CertLimits());

  // 加载自建 CA 根证书（PEM）。检查它是自签名的 CA 证书、在有效期内、时长不超上限。
  bool loadCa(const QByteArray& caPem, QString* error);

  // 加载 CRL（PEM），必须先加载 CA。检查签发者、CA 签名、更新时间；
  // 序号比当前已加载的 CRL 小的拒绝（防止有人用旧 CRL 把已吊销的证书“恢复”）。
  bool loadCrl(const QByteArray& crlPem, QString* error);

  // 校验一张对端证书（DER）。
  // role = Server 时 expectedName 必填；role = Device 时可以留空，名称通过 peer 返回，
  // 由登录处理去和 LOGIN 里的设备 ID 比对。
  CertCheck verify(const QByteArray& certDer, PeerRole role, const QString& expectedName,
                   PeerIdentity* peer) const;

  qint64 loadedCrlNumber() const { return crlNumber_; }
  QDateTime crlNextUpdate() const { return crlNextUpdate_; }

 private:
  bool rebuildStore(QString* error);

  CertLimits limits_;
  X509Ptr ca_;
  X509CrlPtr crl_;
  qint64 crlNumber_ = -1;
  QDateTime crlNextUpdate_;
  OsslPtr<X509_STORE> store_;  // 信任库：只有 ca_ 和 crl_
};

}  // namespace fwds
