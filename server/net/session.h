// Session：服务端的一条设备连接（协议第 4 节的连接状态机）。
// 负责：握手和登录限时、按状态过滤消息、心跳应答、心跳超时判离线。
// LOGIN 的内容由业务层检查，Session 只把消息体交上去，等业务层调 acceptLogin / rejectLogin。
#pragma once

#include <QDateTime>
#include <QHostAddress>
#include <QJsonObject>
#include <QObject>
#include <QTimer>

#include "common/config.h"
#include "common/net/channel_security.h"
#include "common/net/frame_channel.h"

class QSslSocket;

namespace fwds {

class Session : public QObject {
  Q_OBJECT
 public:
  enum class State {
    Handshake,  // TCP 已连接，TLS 握手中
    WaitLogin,  // 信道就绪，等 LOGIN
    Online,     // 已登录
    Closed,
  };

  // socket 的所有权转给 Session。
  Session(quint64 id, QSslSocket* socket, const ProtocolParams& params, ChannelSecurity* security,
          QObject* parent = nullptr);

  // 开始握手并启动登录限时。
  void start();

  // 业务层对 LOGIN 的裁决。result 是 LOGIN_RESULT 的消息体。
  void acceptLogin(const QJsonObject& result);
  void rejectLogin(const QJsonObject& result);

  // ONLINE 状态下向设备发送一帧（UPDATE_NOTIFY、CHUNK_DATA 等）。
  bool send(MsgType type, const QByteArray& body);
  // 发送不关闭连接的 ERROR（3xxx、1005）。
  bool sendError(ErrorCode code, const QString& message = QString());

  // 已交给 socket、还没发到网络上的字节数。分片服务用它做流控：积压太多就先不发新的。
  qint64 pendingSendBytes() const;

  // 业务层更新“已连续收到的最大事件序号”，随 HEARTBEAT_ACK 返回给设备。
  void setEventAck(qint64 eventAck) { eventAck_ = eventAck; }
  // 业务层登记设备 ID，只用于界面显示和日志。
  void setDeviceId(const QString& deviceId) { deviceId_ = deviceId; }

  // 服务端主动断开。
  void close(const QString& reason);

  quint64 id() const { return id_; }
  State state() const { return state_; }
  QHostAddress peerAddress() const { return peerAddress_; }
  quint16 peerPort() const { return peerPort_; }
  QString deviceId() const { return deviceId_; }
  // 对端证书里的身份（握手和补充校验通过后有效）。登录处理用它核对 LOGIN 里的设备 ID。
  const PeerIdentity& peerIdentity() const { return peer_; }
  QDateTime lastHeartbeat() const { return lastHeartbeat_; }

 signals:
  void stateChanged(fwds::Session* session);
  // 收到 LOGIN，等业务层裁决。
  void loginRequested(fwds::Session* session, const QByteArray& body);
  // 收到 HEARTBEAT（应答已发出），body 里是设备上报的状态。
  void heartbeatReceived(fwds::Session* session, const QByteArray& body);
  // ONLINE 状态下收到的其他业务消息。
  void frameReceived(fwds::Session* session, const fwds::Frame& frame);
  // 连接已结束，每个 Session 只发一次。
  void closed(fwds::Session* session, const QString& reason);

 private:
  void onChannelReady();
  void onFrame(const Frame& frame);
  void onPeerError(const Frame& frame);
  void setState(State state);
  void finish(const QString& reason);

  quint64 id_;
  QSslSocket* socket_;
  ProtocolParams params_;
  ChannelSecurity* security_;
  FrameChannel* channel_ = nullptr;
  State state_ = State::Handshake;
  QHostAddress peerAddress_;
  quint16 peerPort_ = 0;
  QString deviceId_;
  PeerIdentity peer_;
  qint64 eventAck_ = 0;
  QDateTime lastHeartbeat_;
  bool loginPending_ = false;  // 已把 LOGIN 交给业务层，还没裁决
  QString closeReason_;
  QTimer loginTimer_;      // 连接建立到登录完成的时限
  QTimer heartbeatTimer_;  // 心跳超时判离线
};

}  // namespace fwds
