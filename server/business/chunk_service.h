// ChunkService：服务端的分片服务（设计第 3 节，协议 5.4 ~ 5.6 节）。
// 负责三件事：
//   1. 记录“哪台设备当前被下发了哪个包”，并发出 UPDATE_NOTIFY / UPDATE_CANCEL；
//   2. 设备断线重连后，把同一个包的 UPDATE_NOTIFY 再发一次，设备据此从断点续传。
//      重发放在重新登录后的第一个心跳：设备登录后先补传 outbox 里的事件，再按周期发心跳，
//      两者走同一条按序到达的连接，所以心跳到的时候补传的 RESULT 已经处理完、下发记录已经删了，
//      已经升级完（或已经回滚）的设备不会再收到这个包的通知（协议 5.4 节）；
//   3. 按 CHUNK_REQ 从 .fwpkg 里读出分片，用 CHUNK_DATA 发回去。
// 服务端从不主动推送分片：设备要一个窗口，这里才发一个窗口（拉取式流控）。
// 给哪些设备下发、什么时候下发由发布模块（RolloutManager）决定，它调用这里的 assign / cancel。
// 下发记录只在内存里，服务端重启后清空；RolloutManager 启动时会把没做完的发布改成“已暂停”。
#pragma once

#include <QHash>
#include <QSet>
#include <QObject>

#include "common/config.h"
#include "common/update_messages.h"
#include "server/business/firmware_repo.h"
#include "server/net/tcp_server.h"

namespace fwds {

class ChunkService : public QObject {
  Q_OBJECT
 public:
  ChunkService(TcpServer* server, const ProtocolParams& params, QObject* parent = nullptr);

  // 把 package 下发给一台在线设备：登记并发送 UPDATE_NOTIFY。
  // 设备不在线时返回 false，什么都不登记——离线设备不缓存、不盲发（设计 4.7 节），
  // 等它上线后由操作员重新确认。
  bool assign(const QString& deviceId, qint64 releaseId, const StoredPackage& package);

  // 取消下发（终止发布、紧急停止）：之后该设备再请求这个包的分片会得到 3009。
  // 设备在线时同时发送 UPDATE_CANCEL。没有下发记录时返回 false。
  bool cancel(const QString& deviceId, const QString& reason);

  // 设备已经上报了这个包的最终结果（RESULT）：删掉下发记录，不发 UPDATE_CANCEL。
  // 之后设备重连不会再收到这个包的通知。下发记录不是这个包时什么都不做。
  void finish(const QString& deviceId, const QString& pkgId);

  // 这台设备当前被下发的包 ID；没有则为空串。
  QString assignedPackage(const QString& deviceId) const;

  // 累计发出的分片数（测试和性能统计用）。
  qint64 chunksSent() const { return chunksSent_; }

 private:
  // 一条下发记录。
  struct Assignment {
    qint64 releaseId = 0;
    StoredPackage package;
  };

  void onSessionStateChanged(Session* session);
  void onSessionClosed(Session* session);
  void onHeartbeat(Session* session);
  void onFrame(Session* session, const Frame& frame);
  void handleChunkRequest(Session* session, const QByteArray& body);
  bool sendNotify(Session* session, const Assignment& assignment);

  ProtocolParams params_;
  QHash<QString, Session*> online_;         // 设备 ID → 它当前已登录的会话
  QHash<QString, Assignment> assignments_;  // 设备 ID → 当前下发给它的包
  QHash<QString, QString> cancelled_;       // 设备 ID → 最近一次被取消的包 ID（区分在途请求和越权请求）
  QSet<QString> resendOnHeartbeat_;         // 重新登录了、还有下发记录，等第一个心跳再重发通知的设备
  qint64 chunksSent_ = 0;
};

}  // namespace fwds
