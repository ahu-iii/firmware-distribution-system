#include "server/net/tcp_server.h"

#include <QSslSocket>

#include "common/log.h"

namespace fwds {

TcpServer::TcpServer(const ServerConfig& config, ChannelSecurity* security, QObject* parent)
    : QTcpServer(parent),
      config_(config),
      security_(security),
      limiter_(config.maxConnections, config.maxConnectionsPerIp) {}

bool TcpServer::start() {
  if (!listen(config_.listenAddress, config_.listenPort)) {
    qCCritical(lcNet) << "listen failed:" << errorString();
    return false;
  }
  qCInfo(lcNet) << "listening on" << serverAddress().toString() << serverPort();
  return true;
}

void TcpServer::incomingConnection(qintptr socketDescriptor) {
  auto* socket = new QSslSocket(this);
  if (!socket->setSocketDescriptor(socketDescriptor)) {
    socket->deleteLater();
    return;
  }

  // 超过连接上限直接断开（2008）。这里不做握手也不发 ERROR 帧：
  // 限制的目的就是不让多余的连接消耗握手资源。
  const QHostAddress peer = socket->peerAddress();
  if (!limiter_.tryAcquire(peer)) {
    qCWarning(lcSecurity) << "connection limit reached, reject" << peer.toString()
                          << "code" << static_cast<int>(ErrorCode::TooManyConnections);
    socket->abort();
    socket->deleteLater();
    return;
  }

  auto* session = new Session(nextSessionId_++, socket, config_.protocol, security_, this);
  sessions_.insert(session->id(), session);
  connect(session, &Session::closed, this, [this, peer](Session* s, const QString& reason) {
    sessions_.remove(s->id());
    limiter_.release(peer);
    emit sessionClosed(s, reason);
    s->deleteLater();
  });
  qCInfo(lcNet) << "session" << session->id() << "opened from" << peer.toString()
                << session->peerPort();
  emit sessionOpened(session);
  session->start();
}

}  // namespace fwds
