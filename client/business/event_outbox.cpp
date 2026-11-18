#include "client/business/event_outbox.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>

#include "client/storage/file_sync.h"
#include "common/log.h"

namespace fwds {

namespace {

// JSON 里的数字是 double。序号必须是正整数，且不超过 double 能精确表示的范围（2^53）。
bool toSeq(const QJsonValue& v, qint64* out) {
  if (!v.isDouble()) return false;
  const double d = v.toDouble();
  if (d < 1 || d > 9007199254740992.0 || d != static_cast<double>(static_cast<qint64>(d))) {
    return false;
  }
  *out = static_cast<qint64>(d);
  return true;
}

bool isEventType(int type) {
  return type == static_cast<int>(MsgType::Progress) || type == static_cast<int>(MsgType::Result) ||
         type == static_cast<int>(MsgType::Alert);
}

QByteArray toLine(const EventOutbox::Event& event) {
  QJsonObject line;
  line.insert(QStringLiteral("type"), static_cast<int>(event.type));
  line.insert(QStringLiteral("body"), event.body);
  return QJsonDocument(line).toJson(QJsonDocument::Compact) + '\n';
}

}  // namespace

EventOutbox::EventOutbox(const QString& dir, SendFn send, QObject* parent)
    : QObject(parent),
      eventsPath_(QDir(dir).filePath(QStringLiteral("events.jsonl"))),
      seqPath_(QDir(dir).filePath(QStringLiteral("seq"))),
      dir_(dir),
      send_(std::move(send)) {}

bool EventOutbox::open(QString* error) {
  pending_.clear();
  lastSeq_ = 0;
  if (!QDir().mkpath(dir_)) {
    *error = QStringLiteral("无法创建事件目录 %1").arg(dir_);
    return false;
  }

  // ① 最近分配的序号。文件不存在（新设备）就是 0
  QFile seqFile(seqPath_);
  if (seqFile.open(QIODevice::ReadOnly)) {
    lastSeq_ = qMax<qint64>(0, seqFile.readAll().trimmed().toLongLong());
  }

  // ② 未确认的事件，一行一个。追加到一半断电会在末尾留下半行，读不出来的行丢掉：
  //    那个事件还没刷盘完成，没有发送过，seq 文件也还没记下它的序号，
  //    下一个事件会重新用这个序号，服务端看到的序号仍然连续
  QFile events(eventsPath_);
  int dropped = 0;
  if (events.open(QIODevice::ReadOnly)) {
    while (!events.atEnd()) {
      const QByteArray line = events.readLine().trimmed();
      if (line.isEmpty()) continue;
      const QJsonObject obj = QJsonDocument::fromJson(line).object();
      Event event;
      const int type = obj.value(QStringLiteral("type")).toInt();
      event.body = obj.value(QStringLiteral("body")).toObject();
      const bool ok = isEventType(type) &&
                      toSeq(event.body.value(QStringLiteral("event_seq")), &event.seq) &&
                      (pending_.isEmpty() || event.seq > pending_.last().seq);
      if (!ok) {
        ++dropped;
        continue;
      }
      event.type = static_cast<MsgType>(type);
      pending_.append(event);
    }
  }
  // seq 文件在事件行之后才写，断电时可能比文件里最大的序号小，取两者中大的
  if (!pending_.isEmpty()) lastSeq_ = qMax(lastSeq_, pending_.last().seq);

  if (dropped > 0) {
    qCWarning(lcApp) << "outbox: dropped" << dropped << "unreadable line(s)";
    // 把文件重写成只含完好的行，否则下一次追加会接在半行后面
    if (!rewriteAll(error)) return false;
  }
  qCInfo(lcApp) << "outbox: last event_seq" << lastSeq_ << "," << pending_.size() << "unconfirmed";
  return true;
}

qint64 EventOutbox::record(MsgType type, const QJsonObject& fields) {
  Event event;
  event.seq = lastSeq_ + 1;
  event.type = type;
  event.body = fields;
  event.body.insert(QStringLiteral("event_seq"), event.seq);
  event.body.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());

  // 先落盘：追加一行并刷盘。失败就不发送——发出去却没落盘的事件，断电后会被同一个序号的新事件顶掉
  QString error;
  if (!appendLine(event, &error)) {
    qCCritical(lcApp).noquote() << "outbox: event not saved:" << error;
    rewriteAll(&error);  // 尽量把可能写了一半的行清掉
    return 0;
  }
  lastSeq_ = event.seq;
  if (!saveSeq(&error)) qCWarning(lcApp).noquote() << "outbox:" << error;
  pending_.append(event);
  emit changed();

  // 再发送。不在线就先留在文件里，等登录后补传
  if (online_) sendOne(event);
  return event.seq;
}

void EventOutbox::onLoggedIn(qint64 eventAck) {
  online_ = true;
  // 服务端确认的序号比本地分配过的还大：本地序号被重置过（例如设备数据目录被清空）。
  // 这时手里的事件序号都 ≤ event_ack，服务端会当成重复丢掉，所以接着服务端的序号重新编号
  if (eventAck > lastSeq_) {
    qCWarning(lcApp) << "outbox: server event_ack" << eventAck << "is ahead of local seq" << lastSeq_
                     << ", renumbering unconfirmed events";
    renumberFrom(eventAck + 1);
  }
  applyAck(eventAck);
  // 补传：剩下的都是服务端没收到的，按序号从小到大重发
  for (const Event& event : pending_) {
    if (!sendOne(event)) break;
  }
}

void EventOutbox::onDisconnected() { online_ = false; }

void EventOutbox::onAcked(qint64 eventAck) { applyAck(eventAck); }

qint64 EventOutbox::confirmedSeq() const {
  // 事件只在被确认后才删除，所以第一条未确认事件之前的都已确认；一条都没有就是全部已确认
  return pending_.isEmpty() ? lastSeq_ : pending_.first().seq - 1;
}

void EventOutbox::applyAck(qint64 eventAck) {
  if (eventAck < 0) return;
  ackedSeq_ = eventAck;
  int confirmed = 0;
  while (confirmed < pending_.size() && pending_.at(confirmed).seq <= eventAck) ++confirmed;
  if (confirmed > 0) {
    pending_.erase(pending_.begin(), pending_.begin() + confirmed);
    // 已确认的从文件里删掉：整个文件重写（先写临时文件再改名）
    QString error;
    if (!rewriteAll(&error)) qCWarning(lcApp).noquote() << "outbox:" << error;
  }
  emit changed();
}

void EventOutbox::renumberFrom(qint64 firstSeq) {
  qint64 seq = firstSeq;
  for (Event& event : pending_) {
    event.seq = seq++;
    event.body.insert(QStringLiteral("event_seq"), event.seq);
  }
  lastSeq_ = seq - 1;
  QString error;
  if (!rewriteAll(&error) || !saveSeq(&error)) qCWarning(lcApp).noquote() << "outbox:" << error;
}

bool EventOutbox::sendOne(const Event& event) {
  return send_(event.type, QJsonDocument(event.body).toJson(QJsonDocument::Compact));
}

bool EventOutbox::appendLine(const Event& event, QString* error) {
  QFile file(eventsPath_);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Append)) {
    *error = QStringLiteral("无法打开 %1：%2").arg(eventsPath_, file.errorString());
    return false;
  }
  const QByteArray line = toLine(event);
  if (file.write(line) != line.size() || !syncToDisk(&file)) {
    *error = QStringLiteral("写 %1 失败：%2").arg(eventsPath_, file.errorString());
    return false;
  }
  return true;
}

bool EventOutbox::rewriteAll(QString* error) {
  // QSaveFile：先写临时文件并刷盘，commit() 时改名覆盖。重写途中断电，留下的是完整的旧文件
  QSaveFile file(eventsPath_);
  if (!file.open(QIODevice::WriteOnly)) {
    *error = QStringLiteral("无法重写 %1：%2").arg(eventsPath_, file.errorString());
    return false;
  }
  for (const Event& event : pending_) file.write(toLine(event));
  if (!file.commit()) {
    *error = QStringLiteral("无法重写 %1：%2").arg(eventsPath_, file.errorString());
    return false;
  }
  return true;
}

bool EventOutbox::saveSeq(QString* error) {
  QSaveFile file(seqPath_);
  if (!file.open(QIODevice::WriteOnly) || file.write(QByteArray::number(lastSeq_)) < 0 ||
      !file.commit()) {
    *error = QStringLiteral("无法保存事件序号 %1：%2").arg(seqPath_, file.errorString());
    return false;
  }
  return true;
}

}  // namespace fwds
