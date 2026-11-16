#include "server/business/device_registry.h"

#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

#include "common/log.h"

namespace fwds {

namespace {

QVariant toIso(const QDateTime& t) {
  return t.isValid() ? QVariant(t.toUTC().toString(Qt::ISODate)) : QVariant();
}

QDateTime fromIso(const QVariant& v) {
  if (v.isNull()) return QDateTime();
  QDateTime t = QDateTime::fromString(v.toString(), Qt::ISODate);
  t.setTimeSpec(Qt::UTC);
  return t;
}

// Qt SQL 把“空的 QString（null）”绑定成数据库的 NULL，而表里这些列是 NOT NULL，
// 所以没填的文本统一存成长度为 0 的字符串。
QString textOrEmpty(const QString& s) { return s.isNull() ? QStringLiteral("") : s; }

}  // namespace

DeviceRegistry::DeviceRegistry(Database* db, QObject* parent) : QObject(parent), db_(db) {}

bool DeviceRegistry::load(QString* error) {
  QSqlQuery q(db_->handle());
  // 上次如果是异常退出，表里可能还留着“在线”，这里统一改回离线
  if (!q.exec(QStringLiteral("UPDATE device SET online_state = 'offline'")) ||
      !q.exec(QStringLiteral(
          "SELECT device_id, model, group_tag, status, cert_fingerprint, cert_not_after, "
          "current_version, security_version, last_heartbeat, event_ack FROM device"))) {
    *error = QStringLiteral("读设备表失败：%1").arg(q.lastError().text());
    return false;
  }
  devices_.clear();
  while (q.next()) {
    DeviceRecord d;
    d.deviceId = q.value(0).toString();
    d.model = q.value(1).toString();
    d.groupTag = q.value(2).toString();
    d.disabled = q.value(3).toString() == QLatin1String("disabled");
    d.certFingerprint = q.value(4).toString();
    d.certNotAfter = fromIso(q.value(5));
    d.currentVersion = q.value(6).toString();
    d.securityVersion = q.value(7).toInt();
    d.lastHeartbeat = fromIso(q.value(8));
    d.eventAck = q.value(9).toLongLong();
    devices_.insert(d.deviceId, d);
  }
  return true;
}

bool DeviceRegistry::find(const QString& deviceId, DeviceRecord* record) const {
  const auto it = devices_.constFind(deviceId);
  if (it == devices_.constEnd()) return false;
  if (record) *record = it.value();
  return true;
}

int DeviceRegistry::onlineCount() const {
  int n = 0;
  for (const DeviceRecord& d : devices_) {
    if (d.online) ++n;
  }
  return n;
}

DeviceCheck DeviceRegistry::checkLogin(const QString& deviceId,
                                       const QString& certFingerprint) const {
  const auto it = devices_.constFind(deviceId);
  if (it == devices_.constEnd()) return DeviceCheck::NotRegistered;
  if (it->disabled) return DeviceCheck::Disabled;
  // 指纹是整张证书的 SHA-256：即使有人拿到 CA 给同一个设备 ID 另签一张证书，
  // 没有经维护员重新注册也登录不了
  if (it->certFingerprint.isEmpty() ||
      it->certFingerprint.compare(certFingerprint, Qt::CaseInsensitive) != 0) {
    return DeviceCheck::FingerprintMismatch;
  }
  return DeviceCheck::Ok;
}

void DeviceRegistry::markOnline(const QString& deviceId, const QString& peerAddress,
                                const QString& fwVersion, int securityVersion) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end()) return;
  it->online = true;
  it->peerAddress = peerAddress;
  it->currentVersion = fwVersion;
  it->securityVersion = securityVersion;
  it->lastHeartbeat = QDateTime::currentDateTimeUtc();
  it->upgradeState.clear();
  it->progress = -1;
  it->alert.clear();

  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "UPDATE device SET online_state = 'online', current_version = ?, security_version = ?, "
      "last_heartbeat = ? WHERE device_id = ?"));
  q.addBindValue(textOrEmpty(fwVersion));
  q.addBindValue(securityVersion);
  q.addBindValue(toIso(it->lastHeartbeat));
  q.addBindValue(deviceId);
  if (!q.exec()) qCWarning(lcApp) << "device table update failed:" << q.lastError().text();
  emit deviceChanged(deviceId);
}

void DeviceRegistry::markHeartbeat(const QString& deviceId, const QString& upgradeState,
                                   int progress) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end()) return;
  // 心跳每 5 秒一次，只更新内存；写库放在登录和下线时，避免每次心跳都刷盘
  it->lastHeartbeat = QDateTime::currentDateTimeUtc();
  it->upgradeState = upgradeState;
  it->progress = progress;
  emit deviceChanged(deviceId);
}

void DeviceRegistry::markOffline(const QString& deviceId) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end() || !it->online) return;
  it->online = false;
  it->peerAddress.clear();

  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "UPDATE device SET online_state = 'offline', last_heartbeat = ? WHERE device_id = ?"));
  q.addBindValue(toIso(it->lastHeartbeat));
  q.addBindValue(deviceId);
  if (!q.exec()) qCWarning(lcApp) << "device table update failed:" << q.lastError().text();
  emit deviceChanged(deviceId);
}

void DeviceRegistry::raiseAlert(const QString& deviceId, const QString& text) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end()) return;
  it->alert = text;
  emit deviceChanged(deviceId);
}

bool DeviceRegistry::addOrUpdateDevice(const DeviceRecord& record, QString* error) {
  const bool existed = devices_.contains(record.deviceId);
  QSqlQuery q(db_->handle());
  if (existed) {
    q.prepare(QStringLiteral(
        "UPDATE device SET model = ?, group_tag = ?, cert_fingerprint = ?, cert_not_after = ? "
        "WHERE device_id = ?"));
  } else {
    q.prepare(QStringLiteral(
        "INSERT INTO device (model, group_tag, cert_fingerprint, cert_not_after, device_id, status) "
        "VALUES (?, ?, ?, ?, ?, 'active')"));
  }
  q.addBindValue(record.model);
  q.addBindValue(textOrEmpty(record.groupTag));
  q.addBindValue(record.certFingerprint);
  q.addBindValue(toIso(record.certNotAfter));
  q.addBindValue(record.deviceId);
  if (!q.exec()) {
    *error = QStringLiteral("写设备表失败：%1").arg(q.lastError().text());
    return false;
  }

  if (existed) {
    DeviceRecord& d = devices_[record.deviceId];
    d.model = record.model;
    d.groupTag = record.groupTag;
    d.certFingerprint = record.certFingerprint;
    d.certNotAfter = record.certNotAfter;
    emit deviceChanged(record.deviceId);
  } else {
    DeviceRecord d;
    d.deviceId = record.deviceId;
    d.model = record.model;
    d.groupTag = record.groupTag;
    d.certFingerprint = record.certFingerprint;
    d.certNotAfter = record.certNotAfter;
    devices_.insert(d.deviceId, d);
    emit deviceAdded(d.deviceId);
  }
  return true;
}

bool DeviceRegistry::setDisabled(const QString& deviceId, bool disabled, QString* error) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end()) {
    *error = QStringLiteral("设备 %1 未注册").arg(deviceId);
    return false;
  }
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("UPDATE device SET status = ? WHERE device_id = ?"));
  q.addBindValue(disabled ? QStringLiteral("disabled") : QStringLiteral("active"));
  q.addBindValue(deviceId);
  if (!q.exec()) {
    *error = QStringLiteral("写设备表失败：%1").arg(q.lastError().text());
    return false;
  }
  it->disabled = disabled;
  emit deviceChanged(deviceId);
  if (disabled) emit deviceDisabled(deviceId);
  return true;
}

bool DeviceRegistry::setGroup(const QString& deviceId, const QString& groupTag, QString* error) {
  const auto it = devices_.find(deviceId);
  if (it == devices_.end()) {
    *error = QStringLiteral("设备 %1 未注册").arg(deviceId);
    return false;
  }
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("UPDATE device SET group_tag = ? WHERE device_id = ?"));
  q.addBindValue(textOrEmpty(groupTag));
  q.addBindValue(deviceId);
  if (!q.exec()) {
    *error = QStringLiteral("写设备表失败：%1").arg(q.lastError().text());
    return false;
  }
  it->groupTag = groupTag;
  emit deviceChanged(deviceId);
  return true;
}

}  // namespace fwds
