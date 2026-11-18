#include "server/business/rollout_manager.h"

#include <QSet>
#include <QSqlError>
#include <QSqlQuery>
#include <QTimer>

#include "common/log.h"

namespace fwds {

namespace {

const QString kSystem = QStringLiteral("system");  // 自动动作的操作者

QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODate); }

QString sqlError(const QSqlQuery& query) {
  return QStringLiteral("数据库操作失败：%1").arg(query.lastError().text());
}

// 设备处于“下载到重启之间”：这时再推一个包会打断正在进行的升级（设计 4.2 节互锁 ②）。
// 状态名是设备在心跳里上报的（协议 6.1 节）。
bool isMidUpgrade(const QString& upgradeState) {
  static const QStringList kBusyStates = {
      QStringLiteral("NOTIFIED"), QStringLiteral("DOWNLOADING"), QStringLiteral("VERIFYING"),
      QStringLiteral("WRITING"), QStringLiteral("REBOOTING")};
  return kBusyStates.contains(upgradeState);
}

// 会向设备推送的状态（“允许下发”关闭时要暂停的就是这两种）。
bool isPushing(const QString& state) {
  return state == QLatin1String("canary") || state == QLatin1String("full");
}

}  // namespace

QString releaseStateText(const QString& state) {
  static const QHash<QString, QString> kText = {
      {QStringLiteral("draft"), QStringLiteral("草稿")},
      {QStringLiteral("canary"), QStringLiteral("灰度中")},
      {QStringLiteral("observing"), QStringLiteral("观察期")},
      {QStringLiteral("awaiting_full"), QStringLiteral("待确认全量")},
      {QStringLiteral("full"), QStringLiteral("全量推送中")},
      {QStringLiteral("paused"), QStringLiteral("已暂停")},
      {QStringLiteral("done"), QStringLiteral("已完成")},
      {QStringLiteral("aborted"), QStringLiteral("已终止")}};
  return kText.value(state, state);
}

QString targetStatusText(const QString& status) {
  static const QHash<QString, QString> kText = {
      {QStringLiteral("pending"), QStringLiteral("排队")},
      {QStringLiteral("held"), QStringLiteral("待确认")},
      {QStringLiteral("notified"), QStringLiteral("升级中")},
      {QStringLiteral("success"), QStringLiteral("成功")},
      {QStringLiteral("failed"), QStringLiteral("失败")},
      {QStringLiteral("rolled_back"), QStringLiteral("已回滚")},
      {QStringLiteral("cancelled"), QStringLiteral("已取消")}};
  return kText.value(status, status);
}

RolloutManager::RolloutManager(Database* db, const ProtocolParams& params,
                               const RolloutParams& rollout, DeviceRegistry* registry,
                               FirmwareRepo* firmware, ChunkService* chunks,
                               const DispatchGate* gate, QObject* parent)
    : QObject(parent),
      db_(db),
      params_(params),
      rollout_(rollout),
      registry_(registry),
      firmware_(firmware),
      chunks_(chunks),
      gate_(gate) {
  // “允许下发”被关闭：正在推送的发布全部暂停，重新打开后要操作员确认才继续
  connect(gate_, &DispatchGate::changed, this, [this](bool enabled) {
    if (enabled) return;
    for (const ReleaseInfo& r : releases(1000)) {
      if (isPushing(r.state)) autoPause(r.releaseId, QStringLiteral("“允许下发”被关闭"));
    }
  });
}

bool RolloutManager::load(QString* error) {
  QSqlQuery query(db_->handle());
  if (!query.exec(QStringLiteral("SELECT release_id FROM \"release\" "
                                 "WHERE state IN ('canary', 'observing', 'full')"))) {
    *error = sqlError(query);
    return false;
  }
  QList<qint64> ids;
  while (query.next()) ids.append(query.value(0).toLongLong());
  for (qint64 id : ids) {
    if (!setState(id, QStringLiteral("paused"), error)) return false;
    notes_.insert(id, QStringLiteral("服务端重启"));
    record(kSystem, QString(), QStringLiteral("发布 #%1 在服务端停止时还在进行，改为已暂停").arg(id), true);
  }
  return true;
}

// ======================= 裁决 =======================

bool RolloutManager::checkGateAndPackage(const QString& pkgId, StoredPackage* package,
                                         QString* error) const {
  // 默认只监控：开关没打开，什么都不推
  if (!gate_->enabled()) {
    *error = QStringLiteral("“允许下发”开关没有打开，当前只监控（需要维护员打开）");
    return false;
  }
  // 固件必须在库里，而且启动时的重新检查是通过的
  if (!firmware_->find(pkgId, package)) {
    *error = QStringLiteral("固件库里没有这个固件包");
    return false;
  }
  if (!package->usable) {
    *error = QStringLiteral("这个固件包不可用：%1").arg(package->problem);
    return false;
  }
  return true;
}

bool RolloutManager::checkModelFree(const QString& model, qint64 exceptId, QString* error) const {
  // 互锁 ①：同一型号同时只允许一个发布处于推送阶段。已暂停的也算——它随时可能被继续
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT r.release_id, r.state FROM \"release\" r JOIN firmware f ON f.pkg_id = r.pkg_id "
      "WHERE f.model = ? AND r.release_id <> ? "
      "AND r.state IN ('canary', 'observing', 'awaiting_full', 'full', 'paused') LIMIT 1"));
  query.addBindValue(model);
  query.addBindValue(exceptId);
  if (!query.exec()) {
    *error = sqlError(query);
    return false;
  }
  if (query.next()) {
    *error = QStringLiteral("型号 %1 已有进行中的发布 #%2（%3）。同一型号同时只能有一个发布，"
                            "请等它完成或终止它")
                 .arg(model)
                 .arg(query.value(0).toLongLong())
                 .arg(releaseStateText(query.value(1).toString()));
    return false;
  }
  return true;
}

bool RolloutManager::checkDevice(const QString& deviceId, const StoredPackage& package,
                                 QString* error) const {
  // 设备已注册、未停用、在线。离线设备不缓存、不盲发
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
    *error = QStringLiteral("设备 %1 不在线").arg(deviceId);
    return false;
  }
  // 型号一致。设备自己还会再查一遍（3002），这里提前拦住明显的误操作
  if (device.model != package.manifest.deviceModel) {
    *error = QStringLiteral("固件适用型号 %1，设备 %2 的型号是 %3")
                 .arg(package.manifest.deviceModel, deviceId, device.model);
    return false;
  }
  // 互锁 ②：设备的状态来自心跳。登录后第一个心跳还没到时状态未知，不推；
  // 处于下载到重启之间时不推；刚下发过、它还没来得及在心跳里上报新状态时也不推
  if (device.upgradeState.isEmpty()) {
    *error = QStringLiteral("设备 %1 登录后还没有上报状态").arg(deviceId);
    return false;
  }
  if (isMidUpgrade(device.upgradeState)) {
    *error = QStringLiteral("设备 %1 正在升级（%2）").arg(deviceId, device.upgradeState);
    return false;
  }
  const QDateTime last = lastDispatchAt_.value(deviceId);
  const qint64 settleMs = 2LL * params_.heartbeatIntervalMs;  // 两个心跳间隔，足够设备上报一次新状态
  if (last.isValid() && last.msecsTo(QDateTime::currentDateTimeUtc()) < settleMs) {
    *error = QStringLiteral("刚向设备 %1 下发过，它还没有上报新状态").arg(deviceId);
    return false;
  }
  return true;
}

// ======================= 管理操作 =======================

bool RolloutManager::dispatchToDevice(const QString& pkgId, const QString& deviceId,
                                      const QString& actor, qint64* releaseId, QString* error) {
  StoredPackage package;
  if (!checkGateAndPackage(pkgId, &package, error) ||
      !checkModelFree(package.manifest.deviceModel, 0, error) ||
      !checkDevice(deviceId, package, error)) {
    return false;
  }
  // 先落库再发通知：UPDATE_NOTIFY 里要带发布号，而且“推过什么”必须有记录。
  // 单台下发记成：没有分组、并发数 1、只有一台金丝雀设备、直接进入灰度的发布
  if (!insertRelease(pkgId, QStringLiteral("canary"), QString(), 1, actor,
                     {{deviceId, QStringLiteral("canary")}}, releaseId, error)) {
    return false;
  }
  if (!chunks_->assign(deviceId, *releaseId, package)) {
    // 裁决之后、发送之前设备刚好掉线：这次下发作废，记录里写明原因
    *error = QStringLiteral("设备 %1 刚刚离线，没有下发").arg(deviceId);
    setTarget(*releaseId, deviceId, QStringLiteral("cancelled"), QStringLiteral("通知前设备离线"));
    setState(*releaseId, QStringLiteral("aborted"));
    emit changed();
    return false;
  }
  lastDispatchAt_.insert(deviceId, QDateTime::currentDateTimeUtc());
  setTarget(*releaseId, deviceId, QStringLiteral("notified"), QString());
  emit changed();
  return true;
}

bool RolloutManager::createRelease(const QString& pkgId, const QStringList& canaryDevices,
                                   const QString& canaryGroup, int concurrency,
                                   const QString& actor, qint64* releaseId, QString* error) {
  // 新建只是写草稿，不推送，所以这里不查“允许下发”开关；开始灰度时才查
  StoredPackage package;
  if (!firmware_->find(pkgId, &package)) {
    *error = QStringLiteral("固件库里没有这个固件包");
    return false;
  }
  if (!package.usable) {
    *error = QStringLiteral("这个固件包不可用：%1").arg(package.problem);
    return false;
  }
  if (concurrency < 1 || concurrency > 100) {
    *error = QStringLiteral("同时推送台数须在 1 ~ 100 之间");
    return false;
  }
  const QString model = package.manifest.deviceModel;
  const QString version = package.manifest.version;

  // 金丝雀：至少一台，每台都要已注册、未停用、型号一致、还不是这个版本
  const QSet<QString> canarySet(canaryDevices.cbegin(), canaryDevices.cend());
  if (canarySet.isEmpty()) {
    *error = QStringLiteral("至少要选一台金丝雀设备");
    return false;
  }
  QList<QPair<QString, QString>> targets;  // (设备 ID, 阶段)
  for (const QString& id : canarySet) {
    DeviceRecord d;
    if (!registry_->find(id, &d)) {
      *error = QStringLiteral("设备 %1 没有注册").arg(id);
      return false;
    }
    if (d.disabled || d.model != model) {
      *error = QStringLiteral("设备 %1 已停用或型号不是 %2，不能作为金丝雀").arg(id, model);
      return false;
    }
    if (d.currentVersion == version) {
      *error = QStringLiteral("设备 %1 已经运行 %2，不能作为金丝雀").arg(id, version);
      return false;
    }
    targets.append({id, QStringLiteral("canary")});
  }
  // 全量批：同型号、未停用、不是金丝雀、还没运行这个版本的全部设备（含当前离线的）
  for (const DeviceRecord& d : registry_->devices()) {
    if (d.model != model || d.disabled || canarySet.contains(d.deviceId)) continue;
    if (d.currentVersion == version) continue;
    targets.append({d.deviceId, QStringLiteral("full")});
  }
  return insertRelease(pkgId, QStringLiteral("draft"), canaryGroup, concurrency, actor, targets,
                       releaseId, error);
}

bool RolloutManager::startCanary(qint64 releaseId, const QString& actor, QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  if (r.state != QLatin1String("draft")) {
    *error = QStringLiteral("只有草稿可以开始灰度（发布 #%1 当前：%2）")
                 .arg(releaseId)
                 .arg(releaseStateText(r.state));
    return false;
  }
  StoredPackage package;
  if (!checkGateAndPackage(r.pkgId, &package, error) ||
      !checkModelFree(package.manifest.deviceModel, releaseId, error) ||
      !setState(releaseId, QStringLiteral("canary"), error)) {
    return false;
  }
  qCInfo(lcApp).noquote() << "release" << releaseId << "canary started by" << actor;
  pushPending(releaseId);
  return true;
}

bool RolloutManager::confirmFull(qint64 releaseId, const QString& actor, QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  // 互锁 ③：未通过灰度（观察期结束、进入“待确认全量”）不能全量
  if (r.state != QLatin1String("awaiting_full")) {
    *error = QStringLiteral("发布 #%1 还没有通过灰度（当前：%2），不能确认全量")
                 .arg(releaseId)
                 .arg(releaseStateText(r.state));
    return false;
  }
  StoredPackage package;
  if (!checkGateAndPackage(r.pkgId, &package, error) ||
      !setState(releaseId, QStringLiteral("full"), error)) {
    return false;
  }
  qCInfo(lcApp).noquote() << "release" << releaseId << "full rollout confirmed by" << actor;
  pushPending(releaseId);
  return true;
}

bool RolloutManager::pause(qint64 releaseId, const QString& actor, QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  static const QStringList kPausable = {QStringLiteral("canary"), QStringLiteral("observing"),
                                        QStringLiteral("awaiting_full"), QStringLiteral("full")};
  if (!kPausable.contains(r.state)) {
    *error = QStringLiteral("发布 #%1 当前是“%2”，不能暂停").arg(releaseId).arg(releaseStateText(r.state));
    return false;
  }
  // 暂停只是不再推新的设备；已经在升级的设备照常完成，结果照常记录
  if (!setState(releaseId, QStringLiteral("paused"), error)) return false;
  notes_.insert(releaseId, QStringLiteral("%1 手动暂停").arg(actor));
  emit changed();
  return true;
}

bool RolloutManager::resume(qint64 releaseId, const QString& actor, QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  if (r.state != QLatin1String("paused")) {
    *error = QStringLiteral("只有已暂停的发布可以继续（发布 #%1 当前：%2）")
                 .arg(releaseId)
                 .arg(releaseStateText(r.state));
    return false;
  }
  StoredPackage package;
  if (!checkGateAndPackage(r.pkgId, &package, error) ||
      !checkModelFree(package.manifest.deviceModel, releaseId, error)) {
    return false;
  }
  // 回到暂停前所在的阶段：全量批里有设备被动过（不再是排队），说明已经进入了全量阶段
  const PhaseCount canary = countPhase(releaseId, QStringLiteral("canary"));
  const PhaseCount full = countPhase(releaseId, QStringLiteral("full"));
  const bool fullStarted = full.pending < full.total;
  QString next;
  if (fullStarted) {
    if (full.failed * 100 > rollout_.maxFailurePct * full.total) {
      *error = QStringLiteral("全量阶段失败 %1 / %2 台，超过阈值 %3%，不能继续，只能终止")
                   .arg(full.failed)
                   .arg(full.total)
                   .arg(rollout_.maxFailurePct);
      return false;
    }
    next = QStringLiteral("full");
  } else {
    // 金丝雀有失败的发布不能继续：继续了也会马上再次暂停。换一个固件包重新建发布
    if (canary.failed > 0 && full.total > 0) {
      *error = QStringLiteral("金丝雀设备有 %1 台失败，未通过灰度，不能继续，只能终止").arg(canary.failed);
      return false;
    }
    next = QStringLiteral("canary");
  }
  if (!setState(releaseId, next, error)) return false;
  notes_.remove(releaseId);
  qCInfo(lcApp).noquote() << "release" << releaseId << "resumed by" << actor << "phase" << next;
  // 服务端重启后分片服务里的下发记录已经没了，“已通知、还没有结果”的设备停在半路，
  // 不会再收到分片（FT-15 联调时发现）。操作员确认继续后给它们重新发一次通知，
  // 设备按断点续传接着下载；不在线的记为待确认，上线后由操作员再推
  for (const QString& deviceId : targetsWithStatus(releaseId, QString(), QStringLiteral("notified"))) {
    if (chunks_->assignedPackage(deviceId) == r.pkgId) continue;  // 没重启过：下发记录还在
    if (chunks_->assign(deviceId, releaseId, package)) {
      lastDispatchAt_.insert(deviceId, QDateTime::currentDateTimeUtc());
      record(kSystem, deviceId, QStringLiteral("发布 #%1：重新通知设备（服务端重启前已通知）").arg(releaseId), false);
    } else {
      setTarget(releaseId, deviceId, QStringLiteral("held"),
                QStringLiteral("服务端重启前已通知，现在不在线，待确认"));
    }
  }
  // 回到灰度阶段时，金丝雀若已全部成功，evaluate 会让它重新进入观察期
  pushPending(releaseId);
  return true;
}

bool RolloutManager::pushHeld(qint64 releaseId, const QString& actor, QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  if (!isPushing(r.state)) {
    *error = QStringLiteral("发布 #%1 当前是“%2”，不在推送阶段").arg(releaseId).arg(releaseStateText(r.state));
    return false;
  }
  const QString phase = r.state;  // canary 或 full，正好就是阶段名
  const QStringList held = targetsWithStatus(releaseId, phase, QStringLiteral("held"));
  if (held.isEmpty()) {
    *error = QStringLiteral("发布 #%1 没有待确认的设备").arg(releaseId);
    return false;
  }
  StoredPackage package;
  if (!checkGateAndPackage(r.pkgId, &package, error)) return false;
  // 操作员确认过了：放回队列，由 pushPending 按并发数推送；仍然不在线的会再次变成待确认
  for (const QString& deviceId : held) {
    setTarget(releaseId, deviceId, QStringLiteral("pending"), QString());
  }
  qCInfo(lcApp).noquote() << "release" << releaseId << held.size() << "held device(s) confirmed by"
                          << actor;
  pushPending(releaseId);
  return true;
}

bool RolloutManager::abort(qint64 releaseId, const QString& actor, bool emergency,
                           QString* error) {
  Release r;
  if (!findRelease(releaseId, &r)) {
    *error = QStringLiteral("没有发布 #%1").arg(releaseId);
    return false;
  }
  // 紧急停止针对正在推送的发布；草稿和已暂停的发布用“终止”（要输口令确认）
  static const QStringList kStoppable = {QStringLiteral("canary"), QStringLiteral("observing"),
                                         QStringLiteral("awaiting_full"), QStringLiteral("full")};
  static const QStringList kTerminable = {QStringLiteral("draft"), QStringLiteral("paused")};
  if (!(emergency ? kStoppable : kTerminable).contains(r.state)) {
    *error = QStringLiteral("发布 #%1 当前是“%2”，不能%3")
                 .arg(releaseId)
                 .arg(releaseStateText(r.state), emergency ? QStringLiteral("紧急停止")
                                                           : QStringLiteral("终止"));
    return false;
  }
  // ① 正在升级的设备：发 UPDATE_CANCEL。写入之前收到的设备放弃升级、保留旧固件；
  //    已经开始写入的设备按正常流程完成或回滚（A/B 保证可回退），结果照常上报
  const QString reason = emergency ? QStringLiteral("emergency_stop") : QStringLiteral("release_aborted");
  const QStringList inFlight = targetsWithStatus(releaseId, QString(), QStringLiteral("notified"));
  for (const QString& deviceId : inFlight) {
    chunks_->cancel(deviceId, reason);
    setTarget(releaseId, deviceId, QStringLiteral("notified"),
              QStringLiteral("已发送取消，等待设备上报结果"));
  }
  // ② 还没推的设备：记为已取消
  for (const QString& status : {QStringLiteral("pending"), QStringLiteral("held")}) {
    for (const QString& deviceId : targetsWithStatus(releaseId, QString(), status)) {
      setTarget(releaseId, deviceId, QStringLiteral("cancelled"), QStringLiteral("发布终止，未推送"));
    }
  }
  // ③ 发布记为已终止
  if (!setState(releaseId, QStringLiteral("aborted"), error)) return false;
  notes_.remove(releaseId);
  qCWarning(lcApp).noquote() << "release" << releaseId << (emergency ? "emergency-stopped" : "aborted")
                             << "by" << actor << "," << inFlight.size() << "device(s) cancelled";
  emit changed();
  return true;
}

// ======================= 推进 =======================

void RolloutManager::pushPending(qint64 releaseId) {
  // 先按已有的结果判断一次：该暂停的先暂停，不能再推下一台（例如全量失败比例刚好超了阈值）
  evaluate(releaseId);
  Release r;
  if (!findRelease(releaseId, &r) || !isPushing(r.state) || !gate_->enabled()) {
    emit changed();
    return;
  }
  StoredPackage package;
  if (!firmware_->find(r.pkgId, &package) || !package.usable) {
    autoPause(releaseId, QStringLiteral("固件包不可用"));
    return;
  }
  const QString phase = r.state;  // canary 或 full
  int inFlight = countPhase(releaseId, phase).notified;
  // 按设备 ID 顺序推，同时在路上的不超过并发数；空出一个位置（有设备上报结果）再推下一台
  for (const QString& deviceId : targetsWithStatus(releaseId, phase, QStringLiteral("pending"))) {
    if (inFlight >= r.concurrency) break;
    QString why;
    if (!checkDevice(deviceId, package, &why)) {
      // 断网不盲发：不在线、正忙的设备不等它、不缓存，记为待确认，由操作员决定什么时候推
      setTarget(releaseId, deviceId, QStringLiteral("held"), why);
      record(kSystem, deviceId, QStringLiteral("发布 #%1：%2，未推送，待确认").arg(releaseId).arg(why));
      continue;
    }
    if (!chunks_->assign(deviceId, releaseId, package)) {
      setTarget(releaseId, deviceId, QStringLiteral("held"), QStringLiteral("通知前设备离线"));
      continue;
    }
    lastDispatchAt_.insert(deviceId, QDateTime::currentDateTimeUtc());
    setTarget(releaseId, deviceId, QStringLiteral("notified"), QString());
    record(kSystem, deviceId, QStringLiteral("发布 #%1：已通知设备（%2批）")
                                  .arg(releaseId)
                                  .arg(phase == QLatin1String("canary") ? QStringLiteral("金丝雀")
                                                                        : QStringLiteral("全量")));
    ++inFlight;
  }
  emit changed();
}

void RolloutManager::evaluate(qint64 releaseId) {
  Release r;
  if (!findRelease(releaseId, &r)) return;
  const PhaseCount canary = countPhase(releaseId, QStringLiteral("canary"));
  const PhaseCount full = countPhase(releaseId, QStringLiteral("full"));

  if (r.state == QLatin1String("canary") || r.state == QLatin1String("observing")) {
    // 灰度阶段或观察期出现失败：还有全量批没推，立即暂停，其余设备不推
    if (canary.failed > 0 && full.total > 0) {
      autoPause(releaseId, QStringLiteral("金丝雀设备有 %1 台升级失败或回滚").arg(canary.failed));
      return;
    }
    if (r.state == QLatin1String("canary") && canary.allFinished()) {
      if (full.total == 0) {
        // 没有全量批（例如单台下发）：金丝雀都有结果，发布就结束了
        setState(releaseId, QStringLiteral("done"));
        record(kSystem, QString(), QStringLiteral("发布 #%1 完成：成功 %2 台，失败 %3 台")
                                       .arg(releaseId)
                                       .arg(canary.success)
                                       .arg(canary.failed));
        return;
      }
      // 金丝雀全部成功：进入观察期，到时由 finishObservation 检查是否稳定
      setState(releaseId, QStringLiteral("observing"));
      const int round = observeRound_.value(releaseId) + 1;
      observeRound_.insert(releaseId, round);
      QTimer::singleShot(rollout_.observeMs, this, [this, releaseId, round]() {
        if (observeRound_.value(releaseId) == round) finishObservation(releaseId);
      });
      record(kSystem, QString(), QStringLiteral("发布 #%1：金丝雀 %2 台全部成功，进入观察期 %3 秒")
                                     .arg(releaseId)
                                     .arg(canary.success)
                                     .arg(rollout_.observeMs / 1000.0));
    }
    return;
  }

  if (r.state == QLatin1String("full")) {
    // 失败台数超过全量批的阈值比例：暂停
    if (full.failed * 100 > rollout_.maxFailurePct * full.total) {
      autoPause(releaseId, QStringLiteral("全量阶段失败 %1 / %2 台，超过阈值 %3%")
                               .arg(full.failed)
                               .arg(full.total)
                               .arg(rollout_.maxFailurePct));
      return;
    }
    if (full.allFinished()) {
      setState(releaseId, QStringLiteral("done"));
      record(kSystem, QString(), QStringLiteral("发布 #%1 完成：全量成功 %2 台，失败 %3 台，取消 %4 台")
                                     .arg(releaseId)
                                     .arg(full.success)
                                     .arg(full.failed)
                                     .arg(full.cancelled));
    }
  }
}

void RolloutManager::finishObservation(qint64 releaseId) {
  Release r;
  if (!findRelease(releaseId, &r) || r.state != QLatin1String("observing")) return;
  StoredPackage package;
  firmware_->find(r.pkgId, &package);
  // 稳定 = 每台金丝雀设备此刻在线，并且运行的就是新版本（重启后重新登录时上报的版本）
  for (const QString& deviceId :
       targetsWithStatus(releaseId, QStringLiteral("canary"), QStringLiteral("success"))) {
    DeviceRecord device;
    if (!registry_->find(deviceId, &device) || !device.online) {
      autoPause(releaseId, QStringLiteral("观察期结束时金丝雀设备 %1 不在线").arg(deviceId));
      return;
    }
    if (device.currentVersion != package.manifest.version) {
      autoPause(releaseId, QStringLiteral("观察期结束时金丝雀设备 %1 运行的是 %2，不是 %3")
                               .arg(deviceId, device.currentVersion, package.manifest.version));
      return;
    }
  }
  setState(releaseId, QStringLiteral("awaiting_full"));
  record(kSystem, QString(), QStringLiteral("发布 #%1：观察期内无失败、无告警，待确认全量").arg(releaseId));
  emit changed();
}

void RolloutManager::autoPause(qint64 releaseId, const QString& reason) {
  Release r;
  if (!findRelease(releaseId, &r)) return;
  static const QStringList kActive = {QStringLiteral("canary"), QStringLiteral("observing"),
                                      QStringLiteral("awaiting_full"), QStringLiteral("full")};
  if (!kActive.contains(r.state)) return;
  if (!setState(releaseId, QStringLiteral("paused"))) return;
  notes_.insert(releaseId, reason);
  record(kSystem, QString(), QStringLiteral("发布 #%1 自动暂停：%2").arg(releaseId).arg(reason), true);
  emit changed();
}

// ======================= 设备事件 =======================

void RolloutManager::onDeviceResult(const QString& deviceId, qint64 releaseId,
                                    const QString& pkgId, const QString& result, int code,
                                    const QString& detail) {
  static const QHash<QString, QString> kStatus = {
      {QStringLiteral("SUCCESS"), QStringLiteral("success")},
      {QStringLiteral("FAILED"), QStringLiteral("failed")},
      {QStringLiteral("ROLLED_BACK"), QStringLiteral("rolled_back")}};
  const QString status = kStatus.value(result);
  if (status.isEmpty()) {
    qCWarning(lcApp).noquote() << "unknown RESULT value from" << deviceId;
    return;
  }
  // 找这台设备、这个包所在的最近一次发布。发布号为 0（设备重启后补报）时只按设备和包找；
  // 包 ID 为空（写完分区后断电、上电时回滚，设备已不知道是哪个包）时，取这台设备正在升级的那一条
  const QString pkg = pkgId.isNull() ? QStringLiteral("") : pkgId;  // 空 QString 会绑成 SQL NULL
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT t.release_id, r.pkg_id FROM release_target t "
      "JOIN \"release\" r ON r.release_id = t.release_id "
      "WHERE t.device_id = ? AND (r.pkg_id = ? OR (? = '' AND t.status = 'notified')) "
      "AND (? = 0 OR t.release_id = ?) "
      "ORDER BY t.release_id DESC LIMIT 1"));
  query.addBindValue(deviceId);
  query.addBindValue(pkg);
  query.addBindValue(pkg);
  query.addBindValue(releaseId);
  query.addBindValue(releaseId);
  if (!query.exec() || !query.next()) {
    qCInfo(lcApp).noquote() << "RESULT from" << deviceId << "does not belong to any release";
    return;
  }
  const qint64 id = query.value(0).toLongLong();
  const QString releasePkgId = query.value(1).toString();
  const QString error = code == 0 ? QString() : QStringLiteral("%1 %2").arg(code).arg(detail.left(120));
  setTarget(id, deviceId, status, error);
  // 有了结果，删掉下发记录：设备重连时不再重发这个包的通知。用发布里的包 ID，回滚时设备报的是空串
  chunks_->finish(deviceId, releasePkgId);

  // 设备上报的结果由 DeviceAudit 记进审计日志（UPGRADE 类），这里只写运行日志
  qCInfo(lcApp).noquote() << QStringLiteral("发布 #%1：设备 %2 上报结果 %3 %4")
                                 .arg(id)
                                 .arg(deviceId, result, error);

  // 推送阶段：空出了一个位置，推下一台并重新判断；观察期：看是否要暂停
  Release r;
  if (!findRelease(id, &r)) return;
  if (isPushing(r.state)) pushPending(id);
  else if (r.state == QLatin1String("observing")) evaluate(id);
  emit changed();
}

void RolloutManager::onDeviceProgress(const QString& deviceId, const QString& pkgId,
                                      const QString& state, int progress) {
  Q_UNUSED(state);  // 阶段名在设备监控页显示（来自心跳），这里只记百分比
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "UPDATE release_target SET progress = ?, updated_at = ? "
      "WHERE device_id = ? AND status = 'notified' "
      "AND release_id IN (SELECT release_id FROM \"release\" WHERE pkg_id = ?)"));
  query.addBindValue(qBound(0, progress, 100));
  query.addBindValue(nowIso());
  query.addBindValue(deviceId);
  query.addBindValue(pkgId);
  if (!query.exec()) {
    qCWarning(lcApp) << "release_target progress update failed:" << query.lastError().text();
    return;
  }
  if (query.numRowsAffected() > 0) emit changed();
}

void RolloutManager::onDeviceAlert(const QString& deviceId, const QString& pkgId, int code,
                                   const QString& detail) {
  // 这台设备所在的、还没结束的发布（告警里带了包 ID 时只找这个包的发布）
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT r.release_id FROM \"release\" r JOIN release_target t ON t.release_id = r.release_id "
      "WHERE t.device_id = ? AND (? = '' OR r.pkg_id = ?) "
      "AND r.state IN ('canary', 'observing', 'awaiting_full', 'full')"));
  const QString pkg = pkgId.isNull() ? QStringLiteral("") : pkgId;  // 空 QString 会绑成 SQL NULL
  query.addBindValue(deviceId);
  query.addBindValue(pkg);
  query.addBindValue(pkg);
  if (!query.exec()) {
    qCWarning(lcApp) << "release query failed:" << query.lastError().text();
    return;
  }
  QList<qint64> ids;
  while (query.next()) ids.append(query.value(0).toLongLong());
  for (qint64 id : ids) {
    // 还有没推的设备才需要暂停；全部推过了（例如单台下发），暂停也拦不住什么，等结果即可
    const PhaseCount canary = countPhase(id, QStringLiteral("canary"));
    const PhaseCount full = countPhase(id, QStringLiteral("full"));
    if (canary.pending + canary.held + full.pending + full.held == 0) continue;
    autoPause(id, QStringLiteral("设备 %1 安全告警 %2 %3").arg(deviceId).arg(code).arg(detail.left(60)));
  }
}

// ======================= 数据库 =======================

bool RolloutManager::findRelease(qint64 releaseId, Release* release) const {
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT pkg_id, state, concurrency FROM \"release\" WHERE release_id = ?"));
  query.addBindValue(releaseId);
  if (!query.exec() || !query.next()) return false;
  release->id = releaseId;
  release->pkgId = query.value(0).toString();
  release->state = query.value(1).toString();
  release->concurrency = query.value(2).toInt();
  return true;
}

bool RolloutManager::setState(qint64 releaseId, const QString& state, QString* error) {
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral("UPDATE \"release\" SET state = ? WHERE release_id = ?"));
  query.addBindValue(state);
  query.addBindValue(releaseId);
  if (!query.exec()) {
    if (error) *error = sqlError(query);
    qCWarning(lcApp) << "release update failed:" << query.lastError().text();
    return false;
  }
  return true;
}

bool RolloutManager::setTarget(qint64 releaseId, const QString& deviceId, const QString& status,
                               const QString& lastError) {
  QSqlQuery query(db_->handle());
  // 成功时进度直接记为 100（设备最后一个 PROGRESS 不一定恰好是 100）
  query.prepare(QStringLiteral(
      "UPDATE release_target SET status = ?, last_error = ?, updated_at = ?, "
      "progress = CASE WHEN ? = 'success' THEN 100 ELSE progress END "
      "WHERE release_id = ? AND device_id = ?"));
  query.addBindValue(status);
  query.addBindValue(lastError.isNull() ? QStringLiteral("") : lastError);  // NOT NULL 列不能绑空 QString
  query.addBindValue(nowIso());
  query.addBindValue(status);
  query.addBindValue(releaseId);
  query.addBindValue(deviceId);
  if (!query.exec()) {
    qCWarning(lcApp) << "release_target update failed:" << query.lastError().text();
    return false;
  }
  return true;
}

RolloutManager::PhaseCount RolloutManager::countPhase(qint64 releaseId, const QString& phase) const {
  PhaseCount c;
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT status, COUNT(*) FROM release_target WHERE release_id = ? AND phase = ? "
      "GROUP BY status"));
  query.addBindValue(releaseId);
  query.addBindValue(phase);
  if (!query.exec()) return c;
  while (query.next()) {
    const QString status = query.value(0).toString();
    const int n = query.value(1).toInt();
    c.total += n;
    if (status == QLatin1String("success")) c.success += n;
    else if (status == QLatin1String("failed") || status == QLatin1String("rolled_back")) c.failed += n;
    else if (status == QLatin1String("notified")) c.notified += n;
    else if (status == QLatin1String("pending")) c.pending += n;
    else if (status == QLatin1String("held")) c.held += n;
    else if (status == QLatin1String("cancelled")) c.cancelled += n;
  }
  return c;
}

QStringList RolloutManager::targetsWithStatus(qint64 releaseId, const QString& phase,
                                              const QString& status) const {
  // phase 为空时不限阶段
  QStringList ids;
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "SELECT device_id FROM release_target WHERE release_id = ? AND (? = '' OR phase = ?) "
      "AND status = ? ORDER BY device_id"));
  query.addBindValue(releaseId);
  query.addBindValue(phase.isNull() ? QStringLiteral("") : phase);
  query.addBindValue(phase.isNull() ? QStringLiteral("") : phase);
  query.addBindValue(status);
  if (!query.exec()) return ids;
  while (query.next()) ids.append(query.value(0).toString());
  return ids;
}

bool RolloutManager::insertRelease(const QString& pkgId, const QString& state,
                                   const QString& canaryGroup, int concurrency,
                                   const QString& actor,
                                   const QList<QPair<QString, QString>>& targets,
                                   qint64* releaseId, QString* error) {
  // 发布和它的目标要么都写进去，要么都不写：放在一个事务里
  QSqlDatabase db = db_->handle();
  if (!db.transaction()) {
    *error = QStringLiteral("数据库操作失败：%1").arg(db.lastError().text());
    return false;
  }
  const QString now = nowIso();
  QSqlQuery release(db);
  release.prepare(QStringLiteral(
      "INSERT INTO \"release\" (pkg_id, state, canary_group, concurrency, created_by, created_at) "
      "VALUES (?, ?, ?, ?, ?, ?)"));
  release.addBindValue(pkgId);
  release.addBindValue(state);
  release.addBindValue(canaryGroup.isNull() ? QStringLiteral("") : canaryGroup);
  release.addBindValue(concurrency);
  release.addBindValue(actor);
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
      "updated_at) VALUES (?, ?, ?, 'pending', 0, '', ?)"));
  for (const auto& [deviceId, phase] : targets) {
    target.addBindValue(*releaseId);
    target.addBindValue(deviceId);
    target.addBindValue(phase);
    target.addBindValue(now);
    if (!target.exec()) {
      *error = sqlError(target);
      db.rollback();
      return false;
    }
  }
  if (!db.commit()) {
    *error = QStringLiteral("数据库操作失败：%1").arg(db.lastError().text());
    db.rollback();
    return false;
  }
  emit changed();
  return true;
}

void RolloutManager::record(const QString& actor, const QString& deviceId, const QString& message,
                            bool warn, const QString& source) {
  if (warn) qCWarning(lcApp).noquote() << message;
  else qCInfo(lcApp).noquote() << message;
  if (!audit_) return;
  audit_->append(audit::kRollout, warn ? QStringLiteral("WARN") : QStringLiteral("INFO"), actor,
                 source.isEmpty() ? AuditService::localSource() : source, deviceId, message);
}

// ======================= 查询 =======================

QList<ReleaseInfo> RolloutManager::releases(int limit) const {
  QList<ReleaseInfo> list;
  QSqlQuery query(db_->handle());
  // 每个发布一行，顺带按状态数一数它的目标设备
  query.prepare(QStringLiteral(
      "SELECT r.release_id, r.pkg_id, f.model, f.version, r.state, r.canary_group, r.concurrency,"
      " r.created_by, r.created_at, COUNT(t.device_id),"
      " SUM(t.phase = 'canary'), SUM(t.status = 'success'),"
      " SUM(t.status IN ('failed', 'rolled_back')), SUM(t.status = 'notified'),"
      " SUM(t.status = 'pending'), SUM(t.status = 'held'), SUM(t.status = 'cancelled') "
      "FROM \"release\" r LEFT JOIN firmware f ON f.pkg_id = r.pkg_id "
      "LEFT JOIN release_target t ON t.release_id = r.release_id "
      "GROUP BY r.release_id ORDER BY r.release_id DESC LIMIT ?"));
  query.addBindValue(limit);
  if (!query.exec()) {
    qCWarning(lcApp) << "release query failed:" << query.lastError().text();
    return list;
  }
  while (query.next()) {
    ReleaseInfo r;
    r.releaseId = query.value(0).toLongLong();
    r.pkgId = query.value(1).toString();
    r.model = query.value(2).toString();
    r.version = query.value(3).toString();
    r.state = query.value(4).toString();
    r.canaryGroup = query.value(5).toString();
    r.concurrency = query.value(6).toInt();
    r.createdBy = query.value(7).toString();
    r.createdAt = QDateTime::fromString(query.value(8).toString(), Qt::ISODate);
    r.total = query.value(9).toInt();
    r.canary = query.value(10).toInt();
    r.success = query.value(11).toInt();
    r.failed = query.value(12).toInt();
    r.notified = query.value(13).toInt();
    r.pending = query.value(14).toInt();
    r.held = query.value(15).toInt();
    r.cancelled = query.value(16).toInt();
    r.note = notes_.value(r.releaseId);
    list.append(r);
  }
  return list;
}

QList<TargetInfo> RolloutManager::targets(qint64 releaseId) const {
  QList<TargetInfo> list;
  QSqlQuery query(db_->handle());
  // 金丝雀排在前面
  query.prepare(QStringLiteral(
      "SELECT device_id, phase, status, progress, last_error, updated_at FROM release_target "
      "WHERE release_id = ? ORDER BY phase = 'full', device_id"));
  query.addBindValue(releaseId);
  if (!query.exec()) return list;
  while (query.next()) {
    TargetInfo t;
    t.deviceId = query.value(0).toString();
    t.phase = query.value(1).toString();
    t.status = query.value(2).toString();
    t.progress = query.value(3).toInt();
    t.lastError = query.value(4).toString();
    t.updatedAt = QDateTime::fromString(query.value(5).toString(), Qt::ISODate);
    list.append(t);
  }
  return list;
}

QList<DispatchRecord> RolloutManager::recentDispatches(int limit) const {
  QList<DispatchRecord> list;
  QSqlQuery query(db_->handle());
  // 每台设备的每次推送一行；还在排队、没推出去的不算“下发记录”
  query.prepare(QStringLiteral(
      "SELECT r.release_id, r.pkg_id, t.device_id, r.state, t.status, t.last_error, r.created_by,"
      " r.created_at FROM \"release\" r JOIN release_target t ON t.release_id = r.release_id "
      "WHERE t.status <> 'pending' ORDER BY r.release_id DESC, t.device_id LIMIT ?"));
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
