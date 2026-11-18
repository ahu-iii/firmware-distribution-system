#include "server/net/session.h"

#include <QJsonDocument>
#include <QSslSocket>

#include "common/log.h"
#include "common/net/channel_security.h"
#include "common/update_messages.h"

namespace fwds {

Session::Session(quint64 id, QSslSocket* socket, const ProtocolParams& params,
                 ChannelSecurity* security, QObject* parent)
    : QObject(parent), id_(id), socket_(socket), params_(params), security_(security) {
  socket_->setParent(this);
  peerAddress_ = socket_->peerAddress();
  peerPort_ = socket_->peerPort();

  loginTimer_.setSingleShot(true);
  heartbeatTimer_.setSingleShot(true);

  connect(&loginTimer_, &QTimer::timeout, this, [this]() {
    qCWarning(lcNet) << "session" << id_ << "login timeout";
    if (channel_) {
      closeReason_ = QStringLiteral("登录超时");
      channel_->fail(ErrorCode::LoginTimeout);
    } else {
      close(QStringLiteral("握手超时"));  // 握手都没完成，没法发 ERROR 帧
    }
  });
  connect(&heartbeatTimer_, &QTimer::timeout, this, [this]() {
    qCWarning(lcNet) << "session" << id_ << deviceId_ << "heartbeat timeout, mark offline";
    close(QStringLiteral("心跳超时"));
  });
  connect(socket_, &QAbstractSocket::disconnected, this, [this]() {
    finish(closeReason_.isEmpty() ? QStringLiteral("对端断开") : closeReason_);
  });
  connect(socket_, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError e) {
    if (e == QAbstractSocket::RemoteHostClosedError) return;  // 由 disconnected 处理
    if (state_ == State::Handshake) {
      // 握手阶段出错：对端没出示证书、证书不被信任、协议版本或套件不符等（协议 6.2 节末）
      qCCritical(lcSecurity).noquote() << "session" << id_ << peerAddress_.toString()
                                       << "TLS handshake failed:" << socket_->errorString();
      close(QStringLiteral("TLS 握手失败"));
      return;
    }
    if (e == QAbstractSocket::SslInternalError) {
      // 握手之后的 TLS 错误：记录的认证标签校验失败，即密文被改动或记录被重放，按安全事件记录
      qCCritical(lcSecurity).noquote() << "session" << id_ << peerAddress_.toString()
                                       << "TLS record rejected:" << socket_->errorString();
      close(QStringLiteral("TLS 记录校验失败"));
      return;
    }
    qCWarning(lcNet) << "session" << id_ << "socket error:" << socket_->errorString();
    close(QStringLiteral("网络错误"));
  });
}

void Session::start() {
  // 限时从 TCP 连接建立算起，覆盖 TLS 握手和登录两个阶段
  loginTimer_.start(params_.loginTimeoutMs);

  // 先 TLS 握手；握手成功后还要过一遍补充校验（吊销、名称），都通过才开始收发 FWDS 帧
  security_->prepare(socket_, true);
  connect(socket_, &QSslSocket::encrypted, this, [this]() {
    const QString reason = security_->verifyPeer(socket_, true, &peer_);
    if (!reason.isEmpty()) {
      qCCritical(lcSecurity).noquote() << "session" << id_ << peerAddress_.toString()
                                       << "peer certificate rejected:" << reason;
      close(QStringLiteral("证书校验失败"));
      return;
    }
    onChannelReady();
  });
  socket_->startServerEncryption();
}

void Session::onChannelReady() {
  channel_ = new FrameChannel(socket_, params_.maxFrameBody, this);
  connect(channel_, &FrameChannel::frameReceived, this, &Session::onFrame);
  connect(channel_, &FrameChannel::protocolError, this,
          [this](ErrorCode code, const QString& message) {
            // 非法帧和序号错误属于安全事件（协议 6.2 节）
            qCCritical(lcSecurity) << "session" << id_ << peerAddress_.toString()
                                   << "frame error" << static_cast<int>(code) << message;
            closeReason_ = QStringLiteral("帧错误 %1").arg(static_cast<int>(code));
          });
  setState(State::WaitLogin);
}

void Session::onFrame(const Frame& frame) {
  const MsgType type = static_cast<MsgType>(frame.type);

  if (state_ == State::WaitLogin) {
    // 登录之前只接受一条 LOGIN
    if (type != MsgType::Login || loginPending_) {
      qCCritical(lcSecurity) << "session" << id_ << "unexpected" << msgTypeName(frame.type)
                             << "before login";
      closeReason_ = QStringLiteral("登录前收到非法消息");
      channel_->fail(ErrorCode::UnexpectedMessage);
      return;
    }
    loginPending_ = true;
    emit loginRequested(this, frame.body);
    return;
  }

  if (state_ != State::Online) return;

  switch (type) {
    case MsgType::Heartbeat: {
      // 消息体格式不对：回复 1005 并丢弃（协议 5.3 节），不应答、不刷新心跳计时，连接不断开
      HeartbeatStatus status;
      if (!parseHeartbeat(frame.body, &status)) {
        qCWarning(lcNet) << "session" << id_ << "malformed HEARTBEAT body, replied 1005";
        sendError(ErrorCode::BadJson);
        break;
      }
      lastHeartbeat_ = QDateTime::currentDateTimeUtc();
      heartbeatTimer_.start(params_.heartbeatTimeoutMs);
      QJsonObject ack;
      ack.insert(QStringLiteral("server_time"), lastHeartbeat_.toMSecsSinceEpoch());
      ack.insert(QStringLiteral("event_ack"), eventAck_);
      channel_->sendJson(MsgType::HeartbeatAck, ack);
      emit heartbeatReceived(this, frame.body);
      emit stateChanged(this);
      break;
    }
    case MsgType::ChunkReq:
    case MsgType::Progress:
    case MsgType::Result:
    case MsgType::Alert:
      emit frameReceived(this, frame);
      break;
    case MsgType::Bye:
      closeReason_ = QStringLiteral("设备正常关闭");
      channel_->closeGracefully();
      break;
    case MsgType::Error:
      onPeerError(frame);
      break;
    default:
      // 其余类型（包括只应由服务端发出的和未定义的）都不允许
      qCCritical(lcSecurity) << "session" << id_ << "unexpected" << msgTypeName(frame.type)
                             << "in ONLINE";
      closeReason_ = QStringLiteral("收到当前状态不允许的消息");
      channel_->fail(ErrorCode::UnexpectedMessage);
      break;
  }
}

void Session::onPeerError(const Frame& frame) {
  const int code = QJsonDocument::fromJson(frame.body).object().value(QStringLiteral("code")).toInt();
  qCWarning(lcNet) << "session" << id_ << "peer reported error" << code;
  if (closesConnection(code)) {
    closeReason_ = QStringLiteral("对端报告错误 %1").arg(code);
    channel_->closeGracefully();
  } else {
    emit frameReceived(this, frame);
  }
}

void Session::acceptLogin(const QJsonObject& result) {
  if (state_ != State::WaitLogin || !loginPending_) return;
  loginPending_ = false;
  loginTimer_.stop();
  channel_->sendJson(MsgType::LoginResult, result);
  lastHeartbeat_ = QDateTime::currentDateTimeUtc();
  heartbeatTimer_.start(params_.heartbeatTimeoutMs);
  setState(State::Online);
}

void Session::rejectLogin(const QJsonObject& result) {
  if (state_ != State::WaitLogin || !loginPending_) return;
  loginPending_ = false;
  loginTimer_.stop();
  closeReason_ = QStringLiteral("登录失败 %1").arg(result.value(QStringLiteral("code")).toInt());
  channel_->sendJson(MsgType::LoginResult, result);
  channel_->closeGracefully();
}

bool Session::send(MsgType type, const QByteArray& body) {
  if (state_ != State::Online) return false;
  return channel_->send(type, body);
}

bool Session::sendError(ErrorCode code, const QString& message) {
  if (!channel_ || state_ == State::Closed) return false;
  return channel_->sendError(code, message);
}

qint64 Session::pendingSendBytes() const {
  // bytesToWrite 是还没加密的明文，encryptedBytesToWrite 是加密后等着写进 TCP 的密文
  return socket_->bytesToWrite() + socket_->encryptedBytesToWrite();
}

void Session::close(const QString& reason) {
  if (state_ == State::Closed) return;
  if (closeReason_.isEmpty()) closeReason_ = reason;
  socket_->abort();
  finish(closeReason_);
}

void Session::setState(State state) {
  if (state_ == state) return;
  state_ = state;
  emit stateChanged(this);
}

void Session::finish(const QString& reason) {
  if (state_ == State::Closed) return;
  loginTimer_.stop();
  heartbeatTimer_.stop();
  state_ = State::Closed;
  qCInfo(lcNet) << "session" << id_ << deviceId_ << "closed:" << reason;
  emit stateChanged(this);
  emit closed(this, reason);
}

}  // namespace fwds
