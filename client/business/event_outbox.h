// EventOutbox：设备事件的“发件箱”（设计 4.6 节，协议 5.7 节）。
// 进度、结果、告警统称事件，每个事件按 “产生 → 落盘 → 发送 → 确认 → 清理” 走：
//   record()     分配下一个 event_seq，先追加到 outbox/events.jsonl 并刷盘，再尝试发送
//   onLoggedIn() 登录成功：按 LOGIN_RESULT 里的 event_ack 删掉已确认的，其余按序号从小到大重发
//   onAcked()    心跳应答里的 event_ack：删掉已确认的
// 不在线时事件照样落盘，只是不发；进程被杀、断电后重新启动，未确认的事件还在文件里。
//
// 文件（都在设备数据目录的 outbox/ 下）：
//   events.jsonl  每行一个未确认事件：{"type":<消息类型>,"body":{...发出去的消息体...}}
//   seq           最近分配的 event_seq（十进制文本）。事件全部确认、events.jsonl 清空之后，
//                 靠它保证序号不回退
#pragma once

#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <functional>

#include "common/protocol.h"

namespace fwds {

class EventOutbox : public QObject {
  Q_OBJECT
 public:
  // 发送一帧的函数，由网络层提供（TcpClient::send）。不在线时返回 false。
  using SendFn = std::function<bool(MsgType, const QByteArray&)>;

  struct Event {
    qint64 seq = 0;
    MsgType type = MsgType::Progress;  // PROGRESS / RESULT / ALERT
    QJsonObject body;                  // 含 event_seq、ts 在内的完整消息体
  };

  // dir 是 outbox 目录（设备数据目录下的 outbox/）。
  EventOutbox(const QString& dir, SendFn send, QObject* parent = nullptr);

  // 读入 seq 和未确认的事件。目录不存在就建出来。程序启动时调用一次。
  bool open(QString* error);

  // 记录一个事件：type 是 PROGRESS / RESULT / ALERT，fields 是除 event_seq、ts 以外的字段。
  // 落盘成功返回分配的序号；落盘失败返回 0（事件丢失，只记日志，不影响升级本身）。
  qint64 record(MsgType type, const QJsonObject& fields);

  // 网络层的两个时刻：登录成功（带 LOGIN_RESULT 的 event_ack）、连接断开。
  void onLoggedIn(qint64 eventAck);
  void onDisconnected();
  // 心跳应答里的 event_ack。
  void onAcked(qint64 eventAck);

  // 已被服务端确认、从本地删掉的最大序号，LOGIN 里作为 event_base 上报（协议 5.1、5.7 节）。
  // 服务端的确认序号比它小，说明服务端丢了已确认过的事件（例如数据库回滚到旧备份），
  // 这些事件设备上已经没有了，服务端据此对账、跳过缺口，而不是一直等下去。
  qint64 confirmedSeq() const;

  // ---- 界面显示用 ----
  int pendingCount() const { return pending_.size(); }
  qint64 lastSeq() const { return lastSeq_; }    // 最近分配的序号
  qint64 ackedSeq() const { return ackedSeq_; }  // 服务端最近确认到的序号
  const QList<Event>& pending() const { return pending_; }

 signals:
  // 未确认事件的数量或确认序号变了。
  void changed();

 private:
  void applyAck(qint64 eventAck);
  void renumberFrom(qint64 firstSeq);
  bool sendOne(const Event& event);
  bool appendLine(const Event& event, QString* error);
  bool rewriteAll(QString* error);
  bool saveSeq(QString* error);

  QString eventsPath_;
  QString seqPath_;
  QString dir_;
  SendFn send_;
  QList<Event> pending_;  // 未确认的事件，按序号从小到大，和 events.jsonl 的内容一致
  qint64 lastSeq_ = 0;
  qint64 ackedSeq_ = 0;
  bool online_ = false;   // 已登录：新事件落盘后立即发送
};

}  // namespace fwds
