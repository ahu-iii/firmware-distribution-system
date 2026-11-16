// TcpServer：监听端口，为每条新连接建一个 Session。
// 基于 QTcpServer，所有连接都在事件循环里非阻塞处理（底层是 IO 多路复用），不为连接开线程。
#pragma once

#include <QHash>
#include <QTcpServer>

#include "common/config.h"
#include "server/net/conn_limiter.h"
#include "server/net/session.h"

namespace fwds {

class TcpServer : public QTcpServer {
  Q_OBJECT
 public:
  // security 由调用方持有，必须比 TcpServer 活得久。
  TcpServer(const ServerConfig& config, ChannelSecurity* security, QObject* parent = nullptr);

  // 按配置的地址和端口开始监听。失败时 errorString() 给出原因。
  bool start();

  QList<Session*> sessions() const { return sessions_.values(); }

 signals:
  void sessionOpened(fwds::Session* session);
  // Session 对象在这个信号的处理函数返回之后才销毁。
  void sessionClosed(fwds::Session* session, const QString& reason);

 protected:
  void incomingConnection(qintptr socketDescriptor) override;

 private:
  ServerConfig config_;
  ChannelSecurity* security_;
  ConnLimiter limiter_;
  quint64 nextSessionId_ = 1;
  QHash<quint64, Session*> sessions_;
};

}  // namespace fwds
