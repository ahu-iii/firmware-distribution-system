#include "client/net/tcp_client.h"

#include <QJsonDocument>
#include <QSslSocket>

#include "common/log.h"
#include "common/net/channel_security.h"

namespace fwds {

TcpClient::TcpClient(const ClientConfig& config, ChannelSecurity* security, QObject* parent)
    : QObject(parent),
      config_(config),
      security_(security),
      backoff_(config.protocol.reconnectBackoffMs) {
  reconnectTimer_.setSingleShot(true);
  loginTimer_.setSingleShot(true);
  connect(&reconnectTimer_, &QTimer::timeout, this, &TcpClient::connectNow);
  connect(&loginTimer_, &QTimer::timeout, this,
          [this]() { dropConnection(QStringLiteral("连接或登录超时")); });
  connect(&heartbeatTimer_, &QTimer::timeout, this, &TcpClient::sendHeartbeat);
}

TcpClient::~TcpClient() { destroySocket(); }

void TcpClient::start() {
  if (state_ != State::Stopped) return;
  backoff_.reset();
  connectNow();
}

void TcpClient::stop(const QString& reason) {
  if (state_ == State::Stopped) return;
  reconnectTimer_.stop();
  loginTimer_.stop();
  heartbeatTimer_.stop();
  if (state_ == State::Online && channel_) {
    QJsonObject bye;
    bye.insert(QStringLiteral("reason"), reason);
    channel_->sendJson(MsgType::Bye, bye);
    socket_->flush();
  }
  setState(State::Stopped);
  destroySocket();
}

void TcpClient::setNetworkBlocked(bool blocked) {
  if (networkBlocked_ == blocked) return;
  networkBlocked_ = blocked;
  qCWarning(lcNet) << (blocked ? "network blocked by demo panel" : "network restored by demo panel");
  if (blocked) {
    dropConnection(QStringLiteral("模拟断网"));  // 已经在等重连或已停止时什么都不做
  } else if (state_ == State::Backoff) {
    reconnectTimer_.stop();
    backoff_.reset();
    connectNow();
  }
}

void TcpClient::connectNow() {
  destroySocket();
  if (networkBlocked_) {
    // 模拟断网中：不发起连接，直接当作连不上，按退避序列再等
    const int delayMs = backoff_.next();
    setState(State::Backoff);
    reconnectTimer_.start(delayMs);
    emit reconnectScheduled(delayMs, QStringLiteral("网络不可达（模拟断网）"));
    return;
  }
  // 每次连接都用新的 socket 和新的 FrameChannel，序号从 1 重新开始
  socket_ = new QSslSocket(this);
  connect(socket_, &QAbstractSocket::disconnected, this,
          [this]() { dropConnection(QStringLiteral("连接断开")); });
  connect(socket_, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError e) {
    if (e == QAbstractSocket::SslInternalError) {
      // TLS 记录校验失败（密文被改动或记录被重放），按安全事件记录后照常断开重连
      qCCritical(lcSecurity).noquote() << "TLS record rejected:" << socket_->errorString();
    }
    dropConnection(QStringLiteral("网络错误：%1").arg(socket_->errorString()));
  });

  setState(State::Connecting);
  loginTimer_.start(config_.protocol.loginTimeoutMs);
  qCInfo(lcNet) << "connecting to" << config_.serverHost << config_.serverPort;

  // 先 TLS 握手（Qt 在握手里校验服务端证书链、有效期和名称），
  // 再做补充校验（吊销等）；都通过才发 LOGIN。任何一步失败都按退避重连，不发送任何业务数据。
  security_->prepare(socket_, false);
  connect(socket_, &QSslSocket::encrypted, this, [this]() {
    PeerIdentity server;
    const QString reason = security_->verifyPeer(socket_, false, &server);
    if (!reason.isEmpty()) {
      qCCritical(lcSecurity).noquote() << "server certificate rejected:" << reason;
      dropConnection(QStringLiteral("服务端证书校验失败"));
      return;
    }
    onChannelReady();
  });
  socket_->connectToHostEncrypted(config_.serverHost, config_.serverPort);
}

void TcpClient::onChannelReady() {
  channel_ = new FrameChannel(socket_, config_.protocol.maxFrameBody, socket_);
  connect(channel_, &FrameChannel::frameReceived, this, &TcpClient::onFrame);
  connect(channel_, &FrameChannel::protocolError, this,
          [](ErrorCode code, const QString& message) {
            qCCritical(lcSecurity) << "frame error from server" << static_cast<int>(code)
                                   << message;
          });

  channel_->sendJson(MsgType::Login, loginProvider_ ? loginProvider_() : QJsonObject());
  setState(State::WaitLogin);
}

void TcpClient::onFrame(const Frame& frame) {
  const MsgType type = static_cast<MsgType>(frame.type);

  if (state_ == State::WaitLogin) {
    if (type == MsgType::LoginResult) {
      onLoginResult(frame);
    } else if (type == MsgType::Error) {
      // 服务端在登录阶段报错（例如 2001 超时）后会断开，这里直接重连
      dropConnection(QStringLiteral("登录阶段服务端报错"));
    } else {
      channel_->fail(ErrorCode::UnexpectedMessage);
    }
    return;
  }
  if (state_ != State::Online) return;

  switch (type) {
    case MsgType::HeartbeatAck:
      sinceLastAck_.restart();
      emit heartbeatAcked(QJsonDocument::fromJson(frame.body).object());
      break;
    case MsgType::UpdateNotify:
    case MsgType::UpdateCancel:
    case MsgType::ChunkData:
      emit frameReceived(frame);
      break;
    case MsgType::Bye:
      dropConnection(QStringLiteral("服务端正常关闭"));
      break;
    case MsgType::Error: {
      const int code =
          QJsonDocument::fromJson(frame.body).object().value(QStringLiteral("code")).toInt();
      qCWarning(lcNet) << "server reported error" << code;
      if (closesConnection(code)) dropConnection(QStringLiteral("服务端报告错误 %1").arg(code));
      else emit frameReceived(frame);
      break;
    }
    default:
      qCCritical(lcSecurity) << "unexpected" << msgTypeName(frame.type) << "from server";
      channel_->fail(ErrorCode::UnexpectedMessage);
      break;
  }
}

void TcpClient::onLoginResult(const Frame& frame) {
  const QJsonObject result = QJsonDocument::fromJson(frame.body).object();
  if (result.value(QStringLiteral("result")).toString() != QLatin1String("OK")) {
    const int code = result.value(QStringLiteral("code")).toInt();
    qCWarning(lcNet) << "login rejected, code" << code;
    emit loginFailed(code);
    dropConnection(QStringLiteral("登录被拒 %1").arg(code));
    return;
  }

  loginTimer_.stop();
  backoff_.reset();  // 登录成功才算恢复，下次断线从最短的等待开始

  // 心跳间隔以服务端下发的为准（单位秒）；没给或为 0 时用本地配置
  int intervalMs = config_.protocol.heartbeatIntervalMs;
  const int serverSeconds = result.value(QStringLiteral("heartbeat_interval")).toInt();
  if (serverSeconds >= 1 && serverSeconds * 1000 < config_.protocol.heartbeatTimeoutMs) {
    intervalMs = serverSeconds * 1000;
  }
  sinceLastAck_.start();
  heartbeatTimer_.start(intervalMs);

  setState(State::Online);
  qCInfo(lcNet) << "login ok, heartbeat every" << intervalMs << "ms";
  emit loggedIn(result);
}

void TcpClient::sendHeartbeat() {
  if (state_ != State::Online) return;
  // 服务端迟迟不应答说明连接已经不可用（半开连接等），主动断开重连
  if (sinceLastAck_.elapsed() > config_.protocol.heartbeatTimeoutMs) {
    dropConnection(QStringLiteral("心跳应答超时"));
    return;
  }
  // 协议 5.3 节要求 state、progress、uptime 三个字段，格式不对服务端回 1005 并丢弃。
  // 业务层没设置（只有网络层单元测试会这样）时报“空闲、没有进度”
  QJsonObject body = heartbeatProvider_ ? heartbeatProvider_() : QJsonObject();
  if (!body.contains(QStringLiteral("state"))) body.insert(QStringLiteral("state"), QStringLiteral("IDLE"));
  if (!body.contains(QStringLiteral("progress"))) body.insert(QStringLiteral("progress"), -1);
  if (!body.contains(QStringLiteral("uptime"))) body.insert(QStringLiteral("uptime"), 0);
  channel_->sendJson(MsgType::Heartbeat, body);
}

bool TcpClient::send(MsgType type, const QByteArray& body) {
  if (state_ != State::Online || !channel_) return false;
  return channel_->send(type, body);
}

bool TcpClient::sendJson(MsgType type, const QJsonObject& body) {
  if (state_ != State::Online || !channel_) return false;
  return channel_->sendJson(type, body);
}

void TcpClient::dropConnection(const QString& reason) {
  if (state_ == State::Stopped || state_ == State::Backoff) return;
  loginTimer_.stop();
  heartbeatTimer_.stop();
  destroySocket();

  const int delayMs = backoff_.next();
  setState(State::Backoff);
  qCWarning(lcNet).noquote() << "connection lost:" << reason << "- retry in" << delayMs << "ms";
  reconnectTimer_.start(delayMs);
  emit reconnectScheduled(delayMs, reason);
}

void TcpClient::destroySocket() {
  if (!socket_) return;
  // 先摘掉信号再关闭，避免 abort() 触发的 disconnected 又回到 dropConnection。
  // 这个函数可能是在 socket 自己的信号处理过程中被调到的，所以用 deleteLater 延后销毁。
  socket_->disconnect(this);
  if (channel_) channel_->disconnect(this);
  socket_->abort();
  socket_->deleteLater();  // channel_ 是 socket_ 的子对象，一起销毁
  socket_ = nullptr;
  channel_ = nullptr;
}

void TcpClient::setState(State state) {
  if (state_ == state) return;
  state_ = state;
  emit stateChanged(state);
}

}  // namespace fwds
