// EventStore：设备事件入库与对账（设计 4.6 节，协议 5.7 节）。
// 设备上报的 PROGRESS / RESULT / ALERT 统称事件，每个事件带设备内单调递增的 event_seq。
//   入库    以 (device_id, event_seq) 为主键写 device_event 表，重复的直接忽略（不重）
//   确认    event_ack = 从 1 开始“已连续收到”的最大序号，存在 device 表，
//           随 LOGIN_RESULT 和 HEARTBEAT_ACK 返回给设备；设备删除 ≤ event_ack 的事件（不丢）
//   暂存    序号跳号的事件先入库暂存，不推进 event_ack，等设备补齐（不乱）
//   处理    event_ack 每推进一格，就把那一格的事件交给业务（界面状态、告警、发布结果），
//           所以业务看到的事件严格按序号、每个只看到一次，补传的也一样
//   对账    设备登录时报告自己已确认删除到哪个序号（event_base）。服务端的 event_ack 比它小，
//           说明服务端丢了设备早已确认过的事件（例如数据库回滚到旧备份），这些事件设备上也没有了：
//           记一条告警说明缺了哪些序号，event_ack 直接推到 event_base，不再干等
// 设备身份一律取自已登录的会话（登录时已和证书核对），不看消息体里的任何自报字段。
#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QObject>

#include "common/protocol.h"
#include "server/business/device_registry.h"
#include "server/storage/database.h"

namespace fwds {

class Session;
class TcpServer;

// 最多暂存多少个“超前”的序号：event_seq 超过 event_ack + 这个数的事件不入库。
// 正常设备按序号从小到大发，不会超前；这个上限防止一台设备用很大的序号把事件表撑满。
inline constexpr qint64 kMaxEventGap = 1000;
// 一个事件的消息体最大字节数。正常事件只有几百字节。
inline constexpr int kMaxEventBody = 4096;

// 界面显示用的一条事件。
struct StoredEvent {
  qint64 seq = 0;
  QDateTime ts;          // 设备上产生的时间
  QString kind;          // progress / result / alert
  QJsonObject payload;   // 设备发来的消息体
  QDateTime receivedAt;  // 服务端入库时间
};

class EventStore : public QObject {
  Q_OBJECT
 public:
  enum class Outcome {
    Stored,       // 入库（可能是暂存，要等补齐）
    Duplicate,    // 收过了，忽略
    Malformed,    // 格式不对，回 1005
    OutOfWindow,  // 序号超前太多，不入库
    StorageError, // 写库失败，不确认，设备之后会重发
  };

  // db、registry 由调用方持有，必须比 EventStore 活得久。
  // server 不为空时自动接收每条会话上的事件帧；单元测试传空，直接调 accept()。
  EventStore(Database* db, DeviceRegistry* registry, TcpServer* server = nullptr,
             QObject* parent = nullptr);

  // 处理一个事件帧。deviceId 取自已登录的会话。
  Outcome accept(const QString& deviceId, MsgType type, const QByteArray& body);

  // 设备登录成功时调用（LoginHandler），按设备报告的 event_base 对账，返回要写进 LOGIN_RESULT 的 event_ack。
  qint64 reconcileOnLogin(const QString& deviceId, qint64 eventBase);

  // ---- 查询（界面用）----
  qint64 eventAck(const QString& deviceId) const;
  // 暂存着的、序号大于 event_ack 的事件数。不为 0 说明中间缺了 event_ack + 1。
  int heldCount(const QString& deviceId) const;
  // 最近 limit 条事件，序号从大到小。
  QList<StoredEvent> recentEvents(const QString& deviceId, int limit) const;

 signals:
  // event_ack 推进到某个事件时发出，每个序号只发一次，按序号先后。
  // 发布模块据此回写发布目标的状态。result 为 SUCCESS / FAILED / ROLLED_BACK；
  // releaseId 为 0 表示设备不知道是哪次发布（写完分区后断电、重新上电才报出结果），按包 ID 匹配。
  void resultStored(const QString& deviceId, qint64 releaseId, const QString& pkgId,
                    const QString& result, int code, const QString& detail);
  void alertStored(const QString& deviceId, const QString& pkgId, int code, const QString& detail);
  void progressStored(const QString& deviceId, const QString& pkgId, const QString& state,
                      int progress);

 private:
  struct Released {  // event_ack 推进时交给业务的一个事件
    QString kind;
    QJsonObject payload;
  };

  void onFrame(Session* session, const Frame& frame);
  bool advance(const QString& deviceId, qint64 floor, qint64* ack, QList<Released>* released);
  bool saveAck(const QString& deviceId, qint64 ack);
  void finish(const QString& deviceId, qint64 ack, const QList<Released>& released);
  void dispatch(const QString& deviceId, const Released& event);

  Database* db_;
  DeviceRegistry* registry_;
};

}  // namespace fwds
