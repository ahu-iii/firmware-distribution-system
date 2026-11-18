#include "server/business/event_store.h"

#include <QJsonDocument>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

#include "common/log.h"
#include "server/net/tcp_server.h"

namespace fwds {

namespace {

// JSON 里的数字是 double：整数要求没有小数部分，且在 double 能精确表示的范围（2^53）之内。
bool toInteger(const QJsonValue& v, qint64 min, qint64* out) {
  if (!v.isDouble()) return false;
  const double d = v.toDouble();
  if (d < static_cast<double>(min) || d > 9007199254740992.0 ||
      d != static_cast<double>(static_cast<qint64>(d))) {
    return false;
  }
  *out = static_cast<qint64>(d);
  return true;
}

bool shortString(const QJsonValue& v, int maxLength) {
  return v.isString() && v.toString().size() <= maxLength;
}

// 检查事件消息体的格式（协议 5.7 节），通过时给出序号和种类。只查格式，不看内容是否“合理”。
bool parseEvent(MsgType type, const QByteArray& body, QJsonObject* event, qint64* seq,
                QString* kind) {
  if (body.size() > kMaxEventBody) return false;
  QJsonParseError error;
  const QJsonDocument doc = QJsonDocument::fromJson(body, &error);
  if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
  const QJsonObject obj = doc.object();

  // 三种事件共有的字段
  qint64 ts = 0;
  if (!toInteger(obj.value(QStringLiteral("event_seq")), 1, seq) ||
      !toInteger(obj.value(QStringLiteral("ts")), 0, &ts) ||
      !shortString(obj.value(QStringLiteral("pkg_id")), 64)) {
    return false;
  }

  qint64 n = 0;
  switch (type) {
    case MsgType::Progress:
      *kind = QStringLiteral("progress");
      if (!shortString(obj.value(QStringLiteral("state")), 16) ||
          !toInteger(obj.value(QStringLiteral("progress")), 0, &n) || n > 100) {
        return false;
      }
      break;
    case MsgType::Result: {
      *kind = QStringLiteral("result");
      const QString result = obj.value(QStringLiteral("result")).toString();
      if ((result != QLatin1String("SUCCESS") && result != QLatin1String("FAILED") &&
           result != QLatin1String("ROLLED_BACK")) ||
          !toInteger(obj.value(QStringLiteral("release_id")), 0, &n) ||
          !toInteger(obj.value(QStringLiteral("code")), 0, &n)) {
        return false;
      }
      break;
    }
    case MsgType::Alert:
      *kind = QStringLiteral("alert");
      if (!toInteger(obj.value(QStringLiteral("code")), 0, &n)) return false;
      break;
    default:
      return false;
  }
  *event = obj;
  return true;
}

QString isoFromMs(qint64 ms) {
  return QDateTime::fromMSecsSinceEpoch(ms, Qt::UTC).toString(Qt::ISODateWithMs);
}

QDateTime fromIso(const QVariant& v) {
  QDateTime t = QDateTime::fromString(v.toString(), Qt::ISODateWithMs);
  t.setTimeSpec(Qt::UTC);
  return t;
}

}  // namespace

EventStore::EventStore(Database* db, DeviceRegistry* registry, TcpServer* server, QObject* parent)
    : QObject(parent), db_(db), registry_(registry) {
  if (server) {
    connect(server, &TcpServer::sessionOpened, this, [this](Session* session) {
      connect(session, &Session::frameReceived, this, &EventStore::onFrame);
    });
  }
}

void EventStore::onFrame(Session* session, const Frame& frame) {
  const MsgType type = static_cast<MsgType>(frame.type);
  if (type != MsgType::Progress && type != MsgType::Result && type != MsgType::Alert) return;
  if (accept(session->deviceId(), type, frame.body) == Outcome::Malformed) {
    session->sendError(ErrorCode::BadJson);  // 1005 不断开（协议 5.8 节）
  }
  // 下一个 HEARTBEAT_ACK 带上最新的确认序号
  session->setEventAck(eventAck(session->deviceId()));
}

EventStore::Outcome EventStore::accept(const QString& deviceId, MsgType type,
                                       const QByteArray& body) {
  // ① 格式
  QJsonObject event;
  qint64 seq = 0;
  QString kind;
  if (!parseEvent(type, body, &event, &seq, &kind)) {
    qCWarning(lcNet).noquote() << "device" << deviceId << "sent a malformed" << msgTypeName(static_cast<quint8>(type));
    return Outcome::Malformed;
  }

  // ② 已确认过的序号：重复（补传时正常会遇到，例如上一条连接上发出的事件服务端收到了、确认还没送到）
  const qint64 ack = eventAck(deviceId);
  if (seq <= ack) return Outcome::Duplicate;
  // ③ 超前太多：不入库
  if (seq > ack + kMaxEventGap) {
    qCWarning(lcSecurity).noquote() << "device" << deviceId << "event_seq" << seq
                                    << "is too far ahead of event_ack" << ack << ", dropped";
    return Outcome::OutOfWindow;
  }

  // ④ 入库，并尽量推进 event_ack。两件事在同一个事务里：要么都写进去，要么都没写
  QSqlDatabase db = db_->handle();
  db.transaction();
  QSqlQuery q(db);
  // 主键 (device_id, event_seq)：已经暂存过的同一序号，INSERT OR IGNORE 不写入
  q.prepare(QStringLiteral(
      "INSERT OR IGNORE INTO device_event (device_id, event_seq, ts, kind, payload, received_at) "
      "VALUES (?, ?, ?, ?, ?, ?)"));
  q.addBindValue(deviceId);
  q.addBindValue(seq);
  q.addBindValue(isoFromMs(event.value(QStringLiteral("ts")).toInteger()));
  q.addBindValue(kind);
  q.addBindValue(QString::fromUtf8(QJsonDocument(event).toJson(QJsonDocument::Compact)));
  q.addBindValue(QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
  if (!q.exec()) {
    qCCritical(lcApp).noquote() << "cannot store event:" << q.lastError().text();
    db.rollback();
    return Outcome::StorageError;
  }
  if (q.numRowsAffected() == 0) {
    db.rollback();
    return Outcome::Duplicate;
  }

  qint64 newAck = ack;
  QList<Released> released;
  if (!advance(deviceId, 0, &newAck, &released) || !db.commit()) {
    qCCritical(lcApp).noquote() << "cannot store event:" << db.lastError().text();
    db.rollback();
    return Outcome::StorageError;
  }
  if (released.isEmpty()) {
    qCInfo(lcNet).noquote() << "device" << deviceId << "event" << seq << "held, waiting for"
                            << ack + 1;
  }
  finish(deviceId, newAck, released);
  return Outcome::Stored;
}

qint64 EventStore::reconcileOnLogin(const QString& deviceId, qint64 eventBase) {
  const qint64 ack = eventAck(deviceId);
  if (eventBase <= ack) return ack;  // 正常情况：服务端知道的不比设备少

  // 设备早已确认并删除到 eventBase，服务端却只连续收到 ack：中间这段服务端没有、设备也没有了
  qCWarning(lcApp).noquote() << "event reconciliation: device" << deviceId << "confirmed up to"
                             << eventBase << "but server has only" << ack << "- events" << ack + 1
                             << "to" << eventBase << "are missing (database restored?), skipping";
  registry_->raiseAlert(deviceId, QStringLiteral("事件对账：服务端缺少序号 %1 ~ %2 的事件")
                                      .arg(ack + 1)
                                      .arg(eventBase));
  QSqlDatabase db = db_->handle();
  db.transaction();
  qint64 newAck = ack;
  QList<Released> released;
  if (!advance(deviceId, eventBase, &newAck, &released) || !db.commit()) {
    qCCritical(lcApp).noquote() << "cannot update event_ack:" << db.lastError().text();
    db.rollback();
    return ack;
  }
  finish(deviceId, newAck, released);
  return newAck;
}

// 从当前 event_ack 往后推：序号 ≤ floor 的、或者正好是下一个序号的，都算“已收到”。
// floor 平时为 0；对账时为设备的 event_base，表示它之前的序号不再等待。
// 调用方已开启事务；这里把新的 event_ack 写进 device 表。
bool EventStore::advance(const QString& deviceId, qint64 floor, qint64* ack,
                         QList<Released>* released) {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "SELECT event_seq, kind, payload FROM device_event "
      "WHERE device_id = ? AND event_seq > ? ORDER BY event_seq"));
  q.addBindValue(deviceId);
  q.addBindValue(*ack);
  if (!q.exec()) return false;
  while (q.next()) {
    const qint64 seq = q.value(0).toLongLong();
    // floor 之前的不再等待；floor 之后必须一个接一个，缺了下一个就停，后面的继续暂存
    if (seq > floor && seq != qMax(*ack, floor) + 1) break;
    *ack = seq;
    released->append({q.value(1).toString(),
                      QJsonDocument::fromJson(q.value(2).toString().toUtf8()).object()});
  }
  *ack = qMax(*ack, floor);
  return saveAck(deviceId, *ack);
}

bool EventStore::saveAck(const QString& deviceId, qint64 ack) {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("UPDATE device SET event_ack = ? WHERE device_id = ?"));
  q.addBindValue(ack);
  q.addBindValue(deviceId);
  return q.exec();
}

void EventStore::finish(const QString& deviceId, qint64 ack, const QList<Released>& released) {
  // 事务已提交，再更新内存里的注册表并交给业务：先落库、后处理
  registry_->noteEventAck(deviceId, ack);
  for (const Released& event : released) dispatch(deviceId, event);
}

void EventStore::dispatch(const QString& deviceId, const Released& event) {
  const QJsonObject& p = event.payload;
  const QString pkgId = p.value(QStringLiteral("pkg_id")).toString();
  const int code = p.value(QStringLiteral("code")).toInt();
  // 设备发来的说明文字只截一小段写日志
  const QString detail = p.value(QStringLiteral("detail")).toString().left(64);

  if (event.kind == QLatin1String("progress")) {
    const QString state = p.value(QStringLiteral("state")).toString();
    const int progress = p.value(QStringLiteral("progress")).toInt();
    registry_->markProgress(deviceId, state, progress);
    emit progressStored(deviceId, pkgId, state, progress);
  } else if (event.kind == QLatin1String("result")) {
    const QString result = p.value(QStringLiteral("result")).toString();
    if (result == QLatin1String("SUCCESS")) {
      qCInfo(lcApp).noquote() << "device" << deviceId << "upgrade succeeded, now running"
                              << p.value(QStringLiteral("fw_version")).toString().left(32);
    } else {
      qCWarning(lcApp).noquote() << "device" << deviceId << "upgrade" << result << "code" << code
                                 << detail;
      registry_->raiseAlert(deviceId, result == QLatin1String("ROLLED_BACK")
                                          ? QStringLiteral("新固件启动失败，已回滚（%1）").arg(code)
                                          : QStringLiteral("升级失败（%1）").arg(code));
    }
    emit resultStored(deviceId,
                      static_cast<qint64>(p.value(QStringLiteral("release_id")).toDouble()), pkgId,
                      result, code, detail);
  } else if (event.kind == QLatin1String("alert")) {
    qCCritical(lcSecurity).noquote() << "device" << deviceId << "security alert" << code << detail;
    registry_->raiseAlert(deviceId, QStringLiteral("设备安全告警 %1").arg(code));
    emit alertStored(deviceId, pkgId, code, detail);
  }
}

qint64 EventStore::eventAck(const QString& deviceId) const {
  DeviceRecord record;
  return registry_->find(deviceId, &record) ? record.eventAck : 0;
}

int EventStore::heldCount(const QString& deviceId) const {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("SELECT COUNT(*) FROM device_event WHERE device_id = ? AND event_seq > ?"));
  q.addBindValue(deviceId);
  q.addBindValue(eventAck(deviceId));
  return q.exec() && q.next() ? q.value(0).toInt() : 0;
}

QList<StoredEvent> EventStore::recentEvents(const QString& deviceId, int limit) const {
  QList<StoredEvent> events;
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "SELECT event_seq, ts, kind, payload, received_at FROM device_event "
      "WHERE device_id = ? ORDER BY event_seq DESC LIMIT ?"));
  q.addBindValue(deviceId);
  q.addBindValue(limit);
  if (!q.exec()) return events;
  while (q.next()) {
    StoredEvent e;
    e.seq = q.value(0).toLongLong();
    e.ts = fromIso(q.value(1));
    e.kind = q.value(2).toString();
    e.payload = QJsonDocument::fromJson(q.value(3).toString().toUtf8()).object();
    e.receivedAt = fromIso(q.value(4));
    events.append(e);
  }
  return events;
}

}  // namespace fwds
