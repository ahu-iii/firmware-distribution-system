#include "server/business/rollout_manager.h"

#include <QSqlError>
#include <QSqlQuery>

#include "common/log.h"

namespace fwds {

namespace {

QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODate); }

QString sqlError(const QSqlQuery& query) {
  return QStringLiteral("数据库操作失败：%1").arg(query.lastError().text());
}

// 设备处于“下载到重启之间”：这时再推一个包会打断正在进行的升级（设计 4.2 节互锁）。
// 状态名是设备在心跳里上报的（协议 6.1 节）。
bool isMidUpgrade(const QString& upgradeState) {
  static const QStringList kBusyStates = {
      QStringLiteral("NOTIFIED"), QStringLiteral("DOWNLOADING"), QStringLiteral("VERIFYING"),
      QStringLiteral("WRITING"), QStringLiteral("REBOOTING")};
  return kBusyStates.contains(upgradeState);
}

}  // namespace

RolloutManager::RolloutManager(Database* db, const ProtocolParams& params,
                               DeviceRegistry* registry, FirmwareRepo* firmware,
                               ChunkService* chunks, const DispatchGate* gate, QObject* parent)
    : QObject(parent),
      db_(db),
      params_(params),
      registry_(registry),
      firmware_(firmware),
      chunks_(chunks),
      gate_(gate) {}

bool RolloutManager::load(QString* error) {
  QSqlQuery query(db_->handle());
  if (!query.exec(QStringLiteral("UPDATE \"release\" SET state = 'paused' "
                                 "WHERE state IN ('canary', 'observing', 'full')"))) {
    *error = sqlError(query);
    return false;
  }
  if (query.numRowsAffected() > 0) {
    qCWarning(lcApp) << query.numRowsAffected()
                     << "release(s) were in progress when the server stopped, now paused";
  }
  return true;
}

bool RolloutManager::checkDispatch(const QString& pkgId, const QString& deviceId,
                                   StoredPackage* package, QString* error) const {
  // ① 默认只监控：开关没打开，什么都不推
  if (!gate_->enabled()) {
    *error = QStringLiteral("“允许下发”开关没有打开，当前只监控（需要维护员打开）");
    return false;
  }
  // ② 固件必须在库里，而且启动时的重新检查是通过的
  if (!firmware_->find(pkgId, package)) {
    *error = QStringLiteral("固件库里没有这个固件包");
    return false;
  }
  if (!package->usable) {
    *error = QStringLiteral("这个固件包不可用：%1").arg(package->problem);
    return false;
  }
  // ③ 设备已注册、未停用、在线。离线设备不缓存、不盲发，等它上线后由操作员重新下发
  DeviceRecord device;
  if (!registry_->find(deviceId, &device)) {
    *error = QStringLiteral("设备 %1 没有注册").arg(deviceId);
    return false;
  }
  if (device.disabled) {
    *error = QStringLiteral("设备 %1 已停用").arg(deviceId);
    return false;
  }
  if (!device.online) {
    *error = QStringLiteral("设备 %1 不在线。离线设备不下发，等它上线后再操作").arg(deviceId);
    return false;
  }
  // ④ 型号一致。设备自己还会再查一遍（3002），这里提前拦住明显的误操作
  if (device.model != package->manifest.deviceModel) {
    *error = QStringLiteral("固件适用型号 %1，设备 %2 的型号是 %3")
                 .arg(package->manifest.deviceModel, deviceId, device.model);
    return false;
  }
  // ⑤ 互锁：设备的状态来自心跳。登录后第一个心跳还没到时状态未知，不下发；
  //    处于下载到重启之间时不下发；刚下发过、它还没来得及在心跳里上报新状态时也不下发
  if (device.upgradeState.isEmpty()) {
    *error = QStringLiteral("设备 %1 登录后还没有上报状态，请稍后再试").arg(deviceId);
    return false;
  }
  if (isMidUpgrade(device.upgradeState)) {
    *error = QStringLiteral("设备 %1 正在升级（%2），完成之前不能再下发")
                 .arg(deviceId, device.upgradeState);
    return false;
  }
  const QDateTime last = lastDispatchAt_.value(deviceId);
  const qint64 settleMs = 2LL * params_.heartbeatIntervalMs;  // 两个心跳间隔，足够设备上报一次新状态
  if (last.isValid() && last.msecsTo(QDateTime::currentDateTimeUtc()) < settleMs) {
    *error = QStringLiteral("刚向设备 %1 下发过，等它上报状态后再试").arg(deviceId);
    return false;
  }
  return true;
}

bool RolloutManager::dispatchToDevice(const QString& pkgId, const QString& deviceId,
                                      const QString& createdBy, qint64* releaseId,
                                      QString* error) {
  StoredPackage package;
  if (!checkDispatch(pkgId, deviceId, &package, error)) {
    qCWarning(lcApp).noquote() << "dispatch rejected:" << deviceId << *error;
    return false;
  }
  // 先落库再发通知：UPDATE_NOTIFY 里要带发布号，而且“推过什么”必须有记录
  if (!insertRelease(pkgId, deviceId, createdBy, releaseId, error)) return false;

  if (!chunks_->assign(deviceId, *releaseId, package)) {
    // 裁决之后、发送之前设备刚好掉线：这次下发作废，记录里写明原因
    *error = QStringLiteral("设备 %1 刚刚离线，没有下发").arg(deviceId);
    markDispatchFailed(*releaseId, deviceId, QStringLiteral("device went offline before notify"));
    emit changed();
    return false;
  }
  lastDispatchAt_.insert(deviceId, QDateTime::currentDateTimeUtc());
  emit changed();
  return true;
}

bool RolloutManager::insertRelease(const QString& pkgId, const QString& deviceId,
                                   const QString& createdBy, qint64* releaseId, QString* error) {
  // 发布和它的目标要么都写进去，要么都不写：放在一个事务里
  QSqlDatabase db = db_->handle();
  if (!db.transaction()) {
    *error = QStringLiteral("数据库操作失败：%1").arg(db.lastError().text());
    return false;
  }
  const QString now = nowIso();
  QSqlQuery release(db);
  // 单台下发：没有分组（canary_group 为空，目标是手动选的），并发数 1，直接进入灰度阶段
  release.prepare(QStringLiteral(
      "INSERT INTO \"release\" (pkg_id, state, canary_group, concurrency, created_by, created_at) "
      "VALUES (?, 'canary', '', 1, ?, ?)"));
  release.addBindValue(pkgId);
  release.addBindValue(createdBy);
  release.addBindValue(now);
  if (!release.exec()) {
    *error = sqlError(release);
    db.rollback();
    return false;
  }
  *releaseId = release.lastInsertId().toLongLong();

  QSqlQuery target(db);
  target.prepare(QStringLiteral(
      "INSERT INTO release_target (release_id, device_id, phase, status, progress, last_error, "
      "updated_at) VALUES (?, ?, 'canary', 'notified', 0, '', ?)"));
  target.addBindValue(*releaseId);
  target.addBindValue(deviceId);
  target.addBindValue(now);
  if (!target.exec()) {
    *error = sqlError(target);
    db.rollback();
    return false;
  }
  if (!db.commit()) {
    *error = QStringLiteral("数据库操作失败：%1").arg(db.lastError().text());
    db.rollback();
    return false;
  }
  return true;
}

void RolloutManager::markDispatchFailed(qint64 releaseId, const QString& deviceId,
                                        const QString& reason) {
  QSqlQuery target(db_->handle());
  target.prepare(QStringLiteral("UPDATE release_target SET status = 'failed', last_error = ?, "
                                "updated_at = ? WHERE release_id = ? AND device_id = ?"));
  target.addBindValue(reason);
  target.addBindValue(nowIso());
  target.addBindValue(releaseId);
  target.addBindValue(deviceId);
  if (!target.exec()) qCWarning(lcApp) << "release_target update failed:" << target.lastError().text();

  QSqlQuery release(db_->handle());
  release.prepare(QStringLiteral("UPDATE \"release\" SET state = 'aborted' WHERE release_id = ?"));
  release.addBindValue(releaseId);
  if (!release.exec()) qCWarning(lcApp) << "release update failed:" << release.lastError().text();
}

QList<DispatchRecord> RolloutManager::recentDispatches(int limit) const {
  QList<DispatchRecord> list;
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT r.release_id, r.pkg_id, t.device_id, r.state, t.status, t.last_error, r.created_by,"
      " r.created_at FROM \"release\" r JOIN release_target t ON t.release_id = r.release_id "
      "ORDER BY r.release_id DESC LIMIT ?"));
  query.addBindValue(limit);
  if (!query.exec()) {
    qCWarning(lcApp) << "release query failed:" << query.lastError().text();
    return list;
  }
  while (query.next()) {
    DispatchRecord record;
    record.releaseId = query.value(0).toLongLong();
    record.pkgId = query.value(1).toString();
    record.deviceId = query.value(2).toString();
    record.releaseState = query.value(3).toString();
    record.targetStatus = query.value(4).toString();
    record.lastError = query.value(5).toString();
    record.createdBy = query.value(6).toString();
    record.createdAt = QDateTime::fromString(query.value(7).toString(), Qt::ISODate);
    list.append(record);
  }
  return list;
}

}  // namespace fwds
