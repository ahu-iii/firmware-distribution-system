// CaStore：签发主机上的 CA 目录（设计 10.1、11.4 节），ca-init / issue-cert / revoke 的实现。
// 目录内容：
//   ca.key      CA 私钥，AES-256-GCM 封装，口令每次使用时人工输入
//   ca.pem      CA 根证书（公开，分发给服务端和每台设备）
//   crl.pem     最新的吊销列表（公开，分发给服务端和每台设备）
//   index.json  签发台账：每张证书的序列号、名称、有效期、指纹、是否已吊销；以及 CRL 序号
// 整个目录只存在于离线的签发主机上，不进仓库。
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>

#include "common/crypto/kdf.h"
#include "common/crypto/secure_buffer.h"
#include "signer/cert_builder.h"

namespace fwds {

// 有效期策略（天）。caDays、leafDays 是上限，来自配置文件 [tls] 的
// max_ca_cert_days / max_cert_days，与服务端和客户端校验时用的是同一组数。
struct SignerPolicy {
  int caDays = 365;
  int leafDays = 90;
  int crlDays = 30;                           // CRL 的有效期，到期前要用 update-crl 重新生成
  int kdfIterations = kKdfDefaultIterations;  // 封装私钥时的 PBKDF2 迭代次数
};

// 台账里的一条记录。
struct IssuedCert {
  QString serialHex;
  QString type;  // "server" 或 "device"
  QString name;
  QDateTime notBefore;
  QDateTime notAfter;
  QString fingerprint;
  QDateTime revokedAt;  // 无效值表示没有被吊销
  QString revokeReason;
  bool revoked() const { return revokedAt.isValid(); }
};

// issue-cert 的产物：交给服务端或设备的四个文件的内容。
struct IssuedFiles {
  QByteArray certPem;
  QByteArray sealedKey;  // 已用口令封装，可以直接落盘
  QByteArray caPem;
  QByteArray crlPem;
  IssuedCert info;
};

inline constexpr int kMinPassphraseLength = 12;

class CaStore {
 public:
  CaStore(const QString& dir, const SignerPolicy& policy);

  QString caCertPath() const;
  QString crlPath() const;

  // ca-init：生成 CA 密钥和自签名根证书，并生成一份空的 CRL。目录里已有 CA 时拒绝覆盖。
  // days 为 0 表示用策略上限；超过上限报错。
  bool init(const QString& commonName, int days, const SecureBuffer& caPassphrase,
            QString* error);

  // issue-cert：生成新的密钥对并签发证书。私钥用 keyPassphrase 封装后返回，明文不落盘。
  bool issue(CertType type, const QString& name, int days, const SecureBuffer& caPassphrase,
             const SecureBuffer& keyPassphrase, IssuedFiles* out, QString* error);

  // revoke：按序列号或名称吊销（两者给一个），并重新生成 CRL。count 返回吊销了几张。
  bool revoke(const QString& serialHex, const QString& name, const QString& reason,
              const SecureBuffer& caPassphrase, int* count, QString* error);

  // update-crl：吊销名单不变，只刷新 CRL 的签发时间和序号（CRL 快到期时用）。
  bool updateCrl(const SecureBuffer& caPassphrase, QString* error);

  // 读取台账。
  bool list(QList<IssuedCert>* certs, QString* error) const;

 private:
  struct Index {
    qint64 crlNumber = 0;
    QList<IssuedCert> certs;
  };

  QString path(const char* fileName) const;
  bool loadCa(const SecureBuffer& caPassphrase, X509Ptr* cert, EvpPkeyPtr* key,
              QString* error) const;
  bool readIndex(Index* index, QString* error) const;
  bool writeIndex(const Index& index, QString* error) const;
  // 按台账里的吊销记录生成新 CRL（序号加 1）并写盘，同时更新台账。
  bool writeCrl(X509* caCert, EVP_PKEY* caKey, Index* index, QString* error) const;

  QString dir_;
  SignerPolicy policy_;
};

// 口令强度的最低要求：至少 kMinPassphraseLength 个字节。
bool isAcceptablePassphrase(const SecureBuffer& passphrase);

// 原子写文件：先写临时文件再改名，中途断电不会留下半个文件。
// ownerOnly 为 true 时把权限设成仅文件所有者可读写（私钥文件）。
bool writeFileAtomic(const QString& path, const QByteArray& content, bool ownerOnly,
                     QString* error);

// 把 issue-cert 的产物写进 outDir：<type>.pem、<type>.key、ca.pem、crl.pem。
// 已存在同名私钥或证书时拒绝覆盖。
bool writeIssuedFiles(const QString& outDir, const IssuedFiles& files, QString* error);

}  // namespace fwds
