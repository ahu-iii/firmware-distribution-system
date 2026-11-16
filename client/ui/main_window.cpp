#include "client/ui/main_window.h"

#include <QDateTime>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QVBoxLayout>

namespace fwds {

namespace {

QString stateText(TcpClient::State state) {
  switch (state) {
    case TcpClient::State::Stopped: return QStringLiteral("已停止");
    case TcpClient::State::Connecting: return QStringLiteral("连接中");
    case TcpClient::State::WaitLogin: return QStringLiteral("登录中");
    case TcpClient::State::Online: return QStringLiteral("在线 / 已登录");
    case TcpClient::State::Backoff: return QStringLiteral("已断开，等待重连");
  }
  return QString();
}

}  // namespace

MainWindow::MainWindow(const ClientConfig& config, TcpClient* client, QWidget* parent)
    : QMainWindow(parent) {
  setWindowTitle(QStringLiteral("设备客户端 %1").arg(config.deviceId));
  resize(560, 380);

  auto* central = new QWidget(this);
  auto* layout = new QVBoxLayout(central);
  auto* form = new QFormLayout;
  stateLabel_ = new QLabel(stateText(client->state()), central);
  ackLabel_ = new QLabel(QStringLiteral("—"), central);
  form->addRow(QStringLiteral("设备 ID"), new QLabel(config.deviceId, central));
  form->addRow(QStringLiteral("型号"), new QLabel(config.model, central));
  form->addRow(QStringLiteral("服务端"),
               new QLabel(QStringLiteral("%1:%2").arg(config.serverHost).arg(config.serverPort),
                          central));
  form->addRow(QStringLiteral("连接状态"), stateLabel_);
  form->addRow(QStringLiteral("最后心跳应答"), ackLabel_);
  layout->addLayout(form);

  log_ = new QPlainTextEdit(central);
  log_->setReadOnly(true);
  log_->setMaximumBlockCount(500);  // 只保留最近 500 行
  layout->addWidget(log_);
  setCentralWidget(central);

  connect(client, &TcpClient::stateChanged, this, [this](TcpClient::State state) {
    stateLabel_->setText(stateText(state));
    appendLog(stateText(state));
  });
  connect(client, &TcpClient::heartbeatAcked, this, [this](const QJsonObject&) {
    ackLabel_->setText(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")));
  });
  connect(client, &TcpClient::loginFailed, this,
          [this](int code) { appendLog(QStringLiteral("登录被拒，错误码 %1").arg(code)); });
  connect(client, &TcpClient::reconnectScheduled, this, [this](int delayMs, const QString& reason) {
    appendLog(QStringLiteral("%1，%2 秒后重连").arg(reason).arg(delayMs / 1000.0, 0, 'f', 1));
  });
}

void MainWindow::appendLog(const QString& line) {
  log_->appendPlainText(
      QStringLiteral("%1  %2")
          .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), line));
}

}  // namespace fwds
