#include "common/security/license.h"

#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSysInfo>

#include "common/crypto/rsa_pss.h"
#include "common/crypto/sha256.h"
#include "common/obfuscated_string.h"

namespace fwds {

namespace {

// 设备 ID 的写法和证书名称相同：1 ~ 64 个字母、数字、点、下划线、横线
bool isValidDeviceId(const QString& id) {
  if (id.isEmpty() || id.size() > 64) return false;
  for (const QChar c : id) {
    if (!(c.isLetterOrNumber() && c.unicode() < 128) && c != QLatin1Char('-') &&
        c != QLatin1Char('_') && c != QLatin1Char('.')) {
      return false;
    }
  }
  return true;
}

bool isHex64(const QString& s) {
  if (s.size() != 64) return false;
  for (const QChar c : s) {
    if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
          (c >= QLatin1Char('a') && c <= QLatin1Char('f')))) {
      return false;
    }
  }
  return true;
}

}  // namespace

QByteArray licenseSignedMessage(const QByteArray& body) { return FWDS_OBF("FWDS-LIC-1") + body; }

QByteArray encodeLicenseBody(const License& license) {
  QJsonObject body;
  body.insert(QStringLiteral("device_id"), license.deviceId);
  body.insert(QStringLiteral("hw_fingerprint"), license.hwFingerprint);
  body.insert(QStringLiteral("issued_at"), license.issuedAtMs);
  body.insert(QStringLiteral("expires_at"), license.expiresAtMs);
  return QJsonDocument(body).toJson(QJsonDocument::Compact);
}

QByteArray encodeLicenseFile(const QByteArray& body, const QByteArray& signature) {
  QJsonObject file;
  file.insert(QStringLiteral("body"), QString::fromLatin1(body.toBase64()));
  file.insert(QStringLiteral("sig"), QString::fromLatin1(signature.toBase64()));
  return QJsonDocument(file).toJson(QJsonDocument::Indented);
}

bool verifyLicense(const QByteArray& fileBytes, const ManifestVerifier& fsk, License* out,
                   QString* error) {
  // 外层只有两个 Base64 字段，先限长再解析
  if (fileBytes.size() > kMaxLicenseFileSize) {
    *error = QStringLiteral("许可证文件过大");
    return false;
  }
  const QJsonObject file = QJsonDocument::fromJson(fileBytes).object();
  const QByteArray body =
      QByteArray::fromBase64(file.value(QStringLiteral("body")).toString().toLatin1());
  const QByteArray sig = QByteArray::fromBase64(file.value(QStringLiteral("sig")).toString().toLatin1());
  if (body.isEmpty() || sig.size() != kFskSignatureSize) {
    *error = QStringLiteral("许可证格式不对");
    return false;
  }
  // 第一步：验签。不通过就返回，下面的 JSON 解析不会执行
  if (!fsk.verifySignature(licenseSignedMessage(body), sig)) {
    *error = QStringLiteral("许可证签名验证失败");
    return false;
  }
  // 第二步：body 已确认出自 FSK，才解析字段
  const QJsonObject b = QJsonDocument::fromJson(body).object();
  License lic;
  lic.deviceId = b.value(QStringLiteral("device_id")).toString();
  lic.hwFingerprint = b.value(QStringLiteral("hw_fingerprint")).toString();
  lic.issuedAtMs = b.value(QStringLiteral("issued_at")).toInteger(-1);
  lic.expiresAtMs = b.value(QStringLiteral("expires_at")).toInteger(-1);
  if (!isValidDeviceId(lic.deviceId) || !isHex64(lic.hwFingerprint) || lic.issuedAtMs <= 0 ||
      lic.expiresAtMs <= lic.issuedAtMs) {
    *error = QStringLiteral("许可证内容不完整");
    return false;
  }
  *out = lic;
  return true;
}

bool checkLicense(const License& license, const QString& deviceId, const QString& hwFingerprint,
                  qint64 nowMs, QString* error) {
  if (license.deviceId != deviceId) {
    *error = QStringLiteral("许可证是签给 %1 的，不是 %2").arg(license.deviceId, deviceId);
    return false;
  }
  if (!hwFingerprint.isEmpty() && license.hwFingerprint != hwFingerprint) {
    // 只显示前 8 位，够人工比对，又不把完整指纹写进日志
    *error = QStringLiteral("许可证绑定的硬件指纹（%1…）与本机（%2…）不符")
                 .arg(license.hwFingerprint.left(8), hwFingerprint.left(8));
    return false;
  }
  if (nowMs >= license.expiresAtMs) {
    *error = QStringLiteral("许可证已于 %1 过期")
                 .arg(QDateTime::fromMSecsSinceEpoch(license.expiresAtMs, Qt::UTC).toString(Qt::ISODate));
    return false;
  }
  return true;
}

QString localHardwareFingerprint() {
  const QByteArray machineId = QSysInfo::machineUniqueId();
  if (machineId.isEmpty()) return QString();
  return QString::fromLatin1(sha256(FWDS_OBF("FWDS-HW-1") + machineId).toHex());
}

bool loadDeviceLicense(const QString& path, const ManifestVerifier& fsk, const QString& deviceId,
                       QByteArray* licenseBytes, QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxLicenseFileSize) {
    *error = QStringLiteral("无法读取许可证 %1").arg(path);
    return false;
  }
  const QByteArray bytes = file.readAll();
  License lic;
  if (!verifyLicense(bytes, fsk, &lic, error)) return false;
  const QString hw = localHardwareFingerprint();
  if (hw.isEmpty()) {
    *error = QStringLiteral("取不到本机的硬件标识，无法核对许可证");
    return false;
  }
  if (!checkLicense(lic, deviceId, hw, QDateTime::currentMSecsSinceEpoch(), error)) return false;
  *licenseBytes = bytes;
  return true;
}

}  // namespace fwds
