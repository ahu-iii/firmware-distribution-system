// TcpClient：设备端到服务端的连接（设计第 3 节 TcpClient / Reconnector / Heartbeat）。
// 负责：连接与握手、发 LOGIN 并等结果、定时心跳、等不到应答主动断开、断线后按退避序列重连。
// LOGIN 和 HEARTBEAT 的消息体由业务层通过回调提供，网络层不关心内容。
#pragma once

#include <QElapsedTimer>
#include <QJsonObject>
#include <QObject>
#include <QTimer>
#include <functional>

#include "common/config.h"
#include "common/net/backoff.h"
#include "common/net/frame_channel.h"

class QSslSocket;

namespace fwds {

class ChannelSecurity;

class TcpClient : public QObject {
  Q_OBJECT
 public:
  enum class State {
    Stopped,     // 未启动或已停止
    Connecting,  // TCP 连接和 TLS 握手中
    WaitLogin,   // 已发 LOGIN，等 LOGIN_RESULT
    Online,      // 已登录
    Backoff,     // 断线，等待重连
  };

  using BodyProvider = std::function<QJsonObject()>;

  // security 由调用方持有，必须比 TcpClient 活得久。
  TcpClient(const ClientConfig& config, ChannelSecurity* security, QObject* parent = nullptr);
  ~TcpClient() override;

  // 业务层提供 LOGIN / HEARTBEAT 的消息体。必须在 start() 之前设置 LOGIN 的。
  void setLoginProvider(BodyProvider provider) { loginProvider_ = std::move(provider); }
  void setHeartbeatProvider(BodyProvider provider) { heartbeatProvider_ = std::move(provider); }

  // 开始连接；断线后自动重连，直到调用 stop()。
  void start();
  // 发 BYE 后断开，不再重连。
  void stop(const QString& reason = QStringLiteral("shutdown"));

  // ONLINE 状态下发送一帧（CHUNK_REQ、PROGRESS 等）。
  bool send(MsgType type, const QByteArray& body);
  bool sendJson(MsgType type, const QJsonObject& body);

  State state() const { return state_; }

 signals:
  void stateChanged(fwds::TcpClient::State state);
  // 登录成功，body 是 LOGIN_RESULT。
  void loggedIn(const QJsonObject& result);
  // 登录被拒，code 是 2xxx。之后仍会按退避重连。
  void loginFailed(int code);
  // 收到心跳应答（服务端时间、事件确认序号）。
  void heartbeatAcked(const QJsonObject& ack);
  // ONLINE 状态下收到的业务消息。
  void frameReceived(const fwds::Frame& frame);
  // 连接断开，delayMs 毫秒后重连。
  void reconnectScheduled(int delayMs, const QString& reason);

 private:
  void connectNow();
  void onChannelReady();
  void onFrame(const Frame& frame);
  void onLoginResult(const Frame& frame);
  void sendHeartbeat();
  void dropConnection(const QString& reason);  // 丢弃当前连接并安排重连
  void destroySocket();
  void setState(State state);

  ClientConfig config_;
  ChannelSecurity* security_;
  BodyProvider loginProvider_;
  BodyProvider heartbeatProvider_;
  QSslSocket* socket_ = nullptr;
  FrameChannel* channel_ = nullptr;
  State state_ = State::Stopped;
  Backoff backoff_;
  QTimer reconnectTimer_;  // 退避等待
  QTimer loginTimer_;      // 连接到登录完成的时限
  QTimer heartbeatTimer_;  // 心跳周期
  QElapsedTimer sinceLastAck_;  // 距上一次心跳应答（或登录成功）过了多久
};

}  // namespace fwds
