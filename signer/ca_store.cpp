#include "signer/ca_store.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

#include "common/crypto/key_file.h"
#include "common/crypto/x509_util.h"

namespace fwds {

namespace {

const qint64 kSecondsPerDay = 24 * 3600;
// 证书的生效时间往前拨 5 分钟，容忍签发主机和使用方之间的少量时钟误差
const qint64 kBackdateSeconds = 300;

bool readFile(const QString& path, QByteArray* content, QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取 %1").arg(path);
    return false;
  }
  *content = file.readAll();
  return true;
}

// days 为 0 取上限；超出 1 ~ 上限 的范围报错。
bool resolveDays(int requested, int maxDays, int* days, QString* error) {
  *days = requested == 0 ? maxDays : requested;
  if (*days < 1 || *days > maxDays) {
    *error = QStringLiteral("有效期必须在 1 ~ %1 天之间（上限来自配置）").arg(maxDays);
    return false;
  }
  return true;
}

QString toIso(const QDateTime& t) {
  return t.isValid() ? t.toUTC().toString(Qt::ISODate) : QString();
}

QDateTime fromIso(const QString& s) {
  return s.isEmpty() ? QDateTime() : QDateTime::fromString(s, Qt::ISODate).toUTC();
}

// 封装一把私钥：导出 PKCS#8 明文到 SecureBuffer，加密后明文随 SecureBuffer 析构清零。
bool sealKey(EVP_PKEY* key, const SecureBuffer& passphrase, int iterations, QByteArray* sealed,
             QString* error) {
  SecureBuffer pkcs8;
  if (!privateKeyToPkcs8(key, &pkcs8)) {
    *error = QStringLiteral("私钥编码失败：%1").arg(lastOpensslError());
    return false;
  }
  return sealPrivateKey(pkcs8, passphrase, sealed, error, iterations);
}

}  // namespace

bool isAcceptablePassphrase(const SecureBuffer& passphrase) {
  return passphrase.size() >= kMinPassphraseLength;
}

bool writeFileAtomic(const QString& path, const QByteArray& content, bool ownerOnly,
                     QString* error) {
  QSaveFile file(path);
  if (!file.open(QIODevice::WriteOnly) || file.write(content) != content.size()) {
    *error = QStringLiteral("无法写入 %1").arg(path);
    return false;
  }
  if (ownerOnly) file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
  if (!file.commit()) {
    *error = QStringLiteral("无法写入 %1").arg(path);
    return false;
  }
  return true;
}

bool writeIssuedFiles(const QString& outDir, const IssuedFiles& files, QString* error) {
  if (!QDir().mkpath(outDir)) {
    *error = QStringLiteral("无法创建目录 %1").arg(outDir);
    return false;
  }
  const QDir dir(outDir);
  const QString certPath = dir.filePath(files.info.type + QStringLiteral(".pem"));
  const QString keyPath = dir.filePath(files.info.type + QStringLiteral(".key"));
  if (QFile::exists(certPath) || QFile::exists(keyPath)) {
    *error = QStringLiteral("%1 里已经有证书或私钥，拒绝覆盖；请换一个输出目录").arg(outDir);
    return false;
  }
  return writeFileAtomic(keyPath, files.sealedKey, true, error) &&
         writeFileAtomic(certPath, files.certPem, false, error) &&
         writeFileAtomic(dir.filePath(QStringLiteral("ca.pem")), files.caPem, false, error) &&
         writeFileAtomic(dir.filePath(QStringLiteral("crl.pem")), files.crlPem, false, error);
}

CaStore::CaStore(const QString& dir, const SignerPolicy& policy) : dir_(dir), policy_(policy) {}

QString CaStore::path(const char* fileName) const {
  return QDir(dir_).filePath(QString::fromLatin1(fileName));
}

QString CaStore::caCertPath() const { return path("ca.pem"); }
QString CaStore::crlPath() const { return path("crl.pem"); }

bool CaStore::init(const QString& commonName, int days, const SecureBuffer& caPassphrase,
                   QString* error) {
  if (QFile::exists(path("ca.key")) || QFile::exists(path("ca.pem"))) {
    *error = QStringLiteral("%1 里已经有 CA，拒绝覆盖").arg(dir_);
    return false;
  }
  if (!isAcceptablePassphrase(caPassphrase)) {
    *error = QStringLiteral("CA 口令至少 %1 个字符").arg(kMinPassphraseLength);
    return false;
  }
  int validDays = 0;
  if (!resolveDays(days, policy_.caDays, &validDays, error)) return false;
  if (commonName.trimmed().isEmpty() || commonName.size() > 64) {
    *error = QStringLiteral("CA 名称不能为空，且不超过 64 个字符");
    return false;
  }
  if (!QDir().mkpath(dir_)) {
    *error = QStringLiteral("无法创建目录 %1").arg(dir_);
    return false;
  }

  const EvpPkeyPtr key = generateEcP256Key();
  if (!key) {
    *error = QStringLiteral("生成 CA 密钥失败：%1").arg(lastOpensslError());
    return false;
  }
  const QDateTime notBefore = QDateTime::currentDateTimeUtc().addSecs(-kBackdateSeconds);
  const QDateTime notAfter = notBefore.addSecs(validDays * kSecondsPerDay);
  const X509Ptr cert = buildRootCert(key.get(), commonName, notBefore, notAfter, error);
  if (!cert) return false;

  QByteArray sealed;
  if (!sealKey(key.get(), caPassphrase, policy_.kdfIterations, &sealed, error)) return false;
  if (!writeFileAtomic(path("ca.key"), sealed, true, error) ||
      !writeFileAtomic(path("ca.pem"), certToPem(cert.get()), false, error)) {
    return false;
  }

  // 空台账 + 第一份（空的）CRL：两端启动时必须有 CRL 可加载
  Index index;
  return writeCrl(cert.get(), key.get(), &index, error);
}

bool CaStore::issue(CertType type, const QString& name, int days,
                    const SecureBuffer& caPassphrase, const SecureBuffer& keyPassphrase,
                    IssuedFiles* out, QString* error) {
  if (!isValidCertName(type, name)) {
    *error = QStringLiteral("证书名称不合法：%1").arg(name);
    return false;
  }
  if (!isAcceptablePassphrase(keyPassphrase)) {
    *error = QStringLiteral("私钥口令至少 %1 个字符").arg(kMinPassphraseLength);
    return false;
  }
  int validDays = 0;
  if (!resolveDays(days, policy_.leafDays, &validDays, error)) return false;

  X509Ptr caCert;
  EvpPkeyPtr caKey;
  Index index;
  if (!loadCa(caPassphrase, &caCert, &caKey, error) || !readIndex(&index, error)) return false;

  // 每张证书一把新密钥：服务端和各台设备互不共用（设计 10.1 节）
  const EvpPkeyPtr leafKey = generateEcP256Key();
  if (!leafKey) {
    *error = QStringLiteral("生成密钥失败：%1").arg(lastOpensslError());
    return false;
  }
  const QDateTime notBefore = QDateTime::currentDateTimeUtc().addSecs(-kBackdateSeconds);
  QDateTime notAfter = notBefore.addSecs(validDays * kSecondsPerDay);
  // 叶子证书不能比 CA 证书活得更久
  const QDateTime caNotAfter = certNotAfter(caCert.get());
  if (notAfter > caNotAfter) notAfter = caNotAfter;

  const X509Ptr cert = buildLeafCert(caCert.get(), caKey.get(), leafKey.get(), type, name,
                                     notBefore, notAfter, error);
  if (!cert) return false;
  if (!sealKey(leafKey.get(), keyPassphrase, policy_.kdfIterations, &out->sealedKey, error)) {
    return false;
  }

  IssuedCert info;
  info.serialHex = certSerialHex(cert.get());
  info.type = type == CertType::Server ? QStringLiteral("server") : QStringLiteral("device");
  info.name = name;
  info.notBefore = certNotBefore(cert.get());
  info.notAfter = certNotAfter(cert.get());
  info.fingerprint = certFingerprintSha256(cert.get());

  // 先记台账再交出证书：台账里没有的证书以后没法按名称吊销
  index.certs.append(info);
  if (!writeIndex(index, error)) return false;

  out->certPem = certToPem(cert.get());
  out->info = info;
  return readFile(caCertPath(), &out->caPem, error) && readFile(crlPath(), &out->crlPem, error);
}

bool CaStore::revoke(const QString& serialHex, const QString& name, const QString& reason,
                     const SecureBuffer& caPassphrase, int* count, QString* error) {
  *count = 0;
  if (serialHex.isEmpty() == name.isEmpty()) {
    *error = QStringLiteral("序列号和名称必须给且只给一个");
    return false;
  }
  X509Ptr caCert;
  EvpPkeyPtr caKey;
  Index index;
  if (!loadCa(caPassphrase, &caCert, &caKey, error) || !readIndex(&index, error)) return false;

  const QDateTime now = QDateTime::currentDateTimeUtc();
  for (IssuedCert& cert : index.certs) {
    const bool match = serialHex.isEmpty()
                           ? cert.name == name
                           : cert.serialHex.compare(serialHex, Qt::CaseInsensitive) == 0;
    if (!match || cert.revoked()) continue;
    cert.revokedAt = now;
    cert.revokeReason = reason;
    ++*count;
  }
  if (*count == 0) {
    *error = QStringLiteral("台账里没有匹配且尚未吊销的证书");
    return false;
  }
  return writeCrl(caCert.get(), caKey.get(), &index, error);
}

bool CaStore::updateCrl(const SecureBuffer& caPassphrase, QString* error) {
  X509Ptr caCert;
  EvpPkeyPtr caKey;
  Index index;
  if (!loadCa(caPassphrase, &caCert, &caKey, error) || !readIndex(&index, error)) return false;
  return writeCrl(caCert.get(), caKey.get(), &index, error);
}

bool CaStore::list(QList<IssuedCert>* certs, QString* error) const {
  Index index;
  if (!readIndex(&index, error)) return false;
  *certs = index.certs;
  return true;
}

bool CaStore::loadCa(const SecureBuffer& caPassphrase, X509Ptr* cert, EvpPkeyPtr* key,
                     QString* error) const {
  QByteArray certPem, sealed;
  if (!readFile(path("ca.pem"), &certPem, error) || !readFile(path("ca.key"), &sealed, error)) {
    return false;
  }
  SecureBuffer pkcs8;
  if (!openPrivateKey(sealed, caPassphrase, &pkcs8, error)) return false;
  *cert = certFromPem(certPem);
  *key = privateKeyFromPkcs8(pkcs8);
  if (!*cert || !*key || X509_check_private_key(cert->get(), key->get()) != 1) {
    *error = QStringLiteral("CA 证书与 CA 私钥不匹配或无法解析");
    return false;
  }
  if (QDateTime::currentDateTimeUtc() > certNotAfter(cert->get())) {
    *error = QStringLiteral("CA 证书已过期，需要重新建立 CA");
    return false;
  }
  return true;
}

bool CaStore::readIndex(Index* index, QString* error) const {
  QByteArray content;
  if (!readFile(path("index.json"), &content, error)) return false;
  QJsonParseError parseError;
  const QJsonDocument doc = QJsonDocument::fromJson(content, &parseError);
  if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
    *error = QStringLiteral("台账 index.json 已损坏");
    return false;
  }
  const QJsonObject root = doc.object();
  index->crlNumber = static_cast<qint64>(root.value(QStringLiteral("crl_number")).toDouble());
  index->certs.clear();
  const QJsonArray certs = root.value(QStringLiteral("certs")).toArray();
  for (const QJsonValue& value : certs) {
    const QJsonObject o = value.toObject();
    IssuedCert cert;
    cert.serialHex = o.value(QStringLiteral("serial")).toString();
    cert.type = o.value(QStringLiteral("type")).toString();
    cert.name = o.value(QStringLiteral("name")).toString();
    cert.notBefore = fromIso(o.value(QStringLiteral("not_before")).toString());
    cert.notAfter = fromIso(o.value(QStringLiteral("not_after")).toString());
    cert.fingerprint = o.value(QStringLiteral("fingerprint_sha256")).toString();
    cert.revokedAt = fromIso(o.value(QStringLiteral("revoked_at")).toString());
    cert.revokeReason = o.value(QStringLiteral("revoke_reason")).toString();
    index->certs.append(cert);
  }
  return true;
}

bool CaStore::writeIndex(const Index& index, QString* error) const {
  QJsonArray certs;
  for (const IssuedCert& cert : index.certs) {
    QJsonObject o;
    o.insert(QStringLiteral("serial"), cert.serialHex);
    o.insert(QStringLiteral("type"), cert.type);
    o.insert(QStringLiteral("name"), cert.name);
    o.insert(QStringLiteral("not_before"), toIso(cert.notBefore));
    o.insert(QStringLiteral("not_after"), toIso(cert.notAfter));
    o.insert(QStringLiteral("fingerprint_sha256"), cert.fingerprint);
    o.insert(QStringLiteral("revoked_at"), toIso(cert.revokedAt));
    o.insert(QStringLiteral("revoke_reason"), cert.revokeReason);
    certs.append(o);
  }
  QJsonObject root;
  root.insert(QStringLiteral("crl_number"), index.crlNumber);
  root.insert(QStringLiteral("certs"), certs);
  return writeFileAtomic(path("index.json"), QJsonDocument(root).toJson(), false, error);
}

bool CaStore::writeCrl(X509* caCert, EVP_PKEY* caKey, Index* index, QString* error) const {
  QList<RevokedEntry> revoked;
  for (const IssuedCert& cert : index->certs) {
    if (cert.revoked()) revoked.append(RevokedEntry{cert.serialHex, cert.revokedAt});
  }
  const QDateTime now = QDateTime::currentDateTimeUtc();
  const qint64 number = index->crlNumber + 1;
  const X509CrlPtr crl = buildCrl(caCert, caKey, revoked, number, now,
                                  now.addSecs(policy_.crlDays * kSecondsPerDay), error);
  if (!crl) return false;

  // 先写台账（记下新序号和吊销状态），再写 CRL
  index->crlNumber = number;
  return writeIndex(*index, error) &&
         writeFileAtomic(crlPath(), crlToPem(crl.get()), false, error);
}

}  // namespace fwds
