#include "server/ui/main_window.h"

#include <QHeaderView>
#include <QLabel>
#include <QStatusBar>
#include <QTableWidget>

#include "server/net/tcp_server.h"

namespace fwds {

namespace {

enum Column { ColId, ColPeer, ColState, ColDevice, ColHeartbeat, ColCount };

QString stateText(Session::State state) {
  switch (state) {
    case Session::State::Handshake: return QStringLiteral("握手中");
    case Session::State::WaitLogin: return QStringLiteral("等待登录");
    case Session::State::Online: return QStringLiteral("在线 / 已登录");
    case Session::State::Closed: return QStringLiteral("已断开");
  }
  return QString();
}

}  // namespace

MainWindow::MainWindow(TcpServer* server, QWidget* parent) : QMainWindow(parent), server_(server) {
  setWindowTitle(QStringLiteral("固件分发服务端"));
  resize(820, 420);

  table_ = new QTableWidget(0, ColCount, this);
  table_->setHorizontalHeaderLabels({QStringLiteral("连接号"), QStringLiteral("对端地址"),
                                     QStringLiteral("状态"), QStringLiteral("设备 ID"),
                                     QStringLiteral("最后心跳（UTC）")});
  table_->horizontalHeader()->setStretchLastSection(true);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  setCentralWidget(table_);

  summary_ = new QLabel(this);
  statusBar()->addWidget(summary_);
  summary_->setText(QStringLiteral("监听 %1:%2，当前连接 0")
                        .arg(server_->serverAddress().toString())
                        .arg(server_->serverPort()));

  connect(server_, &TcpServer::sessionOpened, this, &MainWindow::onSessionOpened);
  connect(server_, &TcpServer::sessionClosed, this,
          [this](Session* s, const QString&) { onSessionClosed(s); });
}

int MainWindow::rowOf(quint64 sessionId) const {
  for (int row = 0; row < table_->rowCount(); ++row) {
    if (table_->item(row, ColId)->data(Qt::UserRole).toULongLong() == sessionId) return row;
  }
  return -1;
}

void MainWindow::onSessionOpened(Session* session) {
  const int row = table_->rowCount();
  table_->insertRow(row);
  for (int col = 0; col < ColCount; ++col) table_->setItem(row, col, new QTableWidgetItem);
  table_->item(row, ColId)->setData(Qt::UserRole, session->id());
  table_->item(row, ColId)->setText(QString::number(session->id()));
  table_->item(row, ColPeer)->setText(
      QStringLiteral("%1:%2").arg(session->peerAddress().toString()).arg(session->peerPort()));
  connect(session, &Session::stateChanged, this, &MainWindow::refreshRow);
  refreshRow(session);
}

void MainWindow::refreshRow(Session* session) {
  const int row = rowOf(session->id());
  if (row < 0) return;
  table_->item(row, ColState)->setText(stateText(session->state()));
  table_->item(row, ColDevice)->setText(session->deviceId());
  table_->item(row, ColHeartbeat)
      ->setText(session->lastHeartbeat().toString(QStringLiteral("HH:mm:ss.zzz")));
  summary_->setText(QStringLiteral("监听 %1:%2，当前连接 %3")
                        .arg(server_->serverAddress().toString())
                        .arg(server_->serverPort())
                        .arg(server_->sessions().size()));
}

void MainWindow::onSessionClosed(Session* session) {
  const int row = rowOf(session->id());
  if (row >= 0) table_->removeRow(row);
  summary_->setText(QStringLiteral("监听 %1:%2，当前连接 %3")
                        .arg(server_->serverAddress().toString())
                        .arg(server_->serverPort())
                        .arg(server_->sessions().size()));
}

}  // namespace fwds
