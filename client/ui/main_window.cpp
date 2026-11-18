#include "client/ui/main_window.h"

#include <QDateTime>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QVBoxLayout>

#include "client/ui/demo_panel.h"

namespace fwds {

namespace {

QString stateText(TcpClient::State state) {
  switch (state) {
    case TcpClient::State::Stopped: return QStringLiteral("已停止");
    case TcpClient::State::Connecting: return QStringLiteral("连接中");
    case TcpClient::State::WaitLogin: return QStringLiteral("登录中");
    case TcpClient::State::Online: return QStringLiteral("在线 / 已登录");
    case TcpClient::State::Backoff: return QStringLiteral("离线运行（已断开，等待重连）");
  }
  return QString();
}

QString updateText(Updater::State state) {
  switch (state) {
    case Updater::State::Idle: return QStringLiteral("空闲");
    case Updater::State::Notified: return QStringLiteral("已收到升级通知，检查通过");
    case Updater::State::Downloading: return QStringLiteral("下载中");
    case Updater::State::Verifying: return QStringLiteral("校验中");
    case Updater::State::Writing: return QStringLiteral("写入中");
    case Updater::State::Rebooting: return QStringLiteral("重启中");
    case Updater::State::Success: return QStringLiteral("升级成功");
    case Updater::State::Failed: return QStringLiteral("升级失败（原固件不受影响）");
    case Updater::State::RolledBack: return QStringLiteral("新固件启动失败，已回滚");
  }
  return QString();
}

}  // namespace

MainWindow::MainWindow(const ClientConfig& config, TcpClient* client, Updater* updater,
                       EventOutbox* outbox, QWidget* parent)
    : QMainWindow(parent), updater_(updater), outbox_(outbox) {
  setWindowTitle(QStringLiteral("设备客户端 %1").arg(config.deviceId));
  resize(640, 540);

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
  firmwareLabel_ = new QLabel(central);
  slotLabel_ = new QLabel(central);
  updateLabel_ = new QLabel(updateText(updater->state()), central);
  progressBar_ = new QProgressBar(central);
  progressBar_->setRange(0, 100);
  form->addRow(QStringLiteral("当前固件"), firmwareLabel_);
  form->addRow(QStringLiteral("A/B 分区"), slotLabel_);
  form->addRow(QStringLiteral("升级状态"), updateLabel_);
  form->addRow(QStringLiteral("升级进度"), progressBar_);
  outboxLabel_ = new QLabel(central);
  form->addRow(QStringLiteral("待上报事件"), outboxLabel_);
  layout->addLayout(form);
  showFirmware();
  showOutbox();

  auto* demo = new DemoPanel(config.dataDir, client, updater, central);
  layout->addWidget(demo);

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

  // 升级状态机的状态、进度、结果、告警
  connect(updater, &Updater::stateChanged, this, [this](Updater::State state) {
    updateLabel_->setText(updateText(state));
    progressBar_->setValue(updater_->progress());
    appendLog(updateText(state));
    showFirmware();  // 重启之后运行的固件和活动分区可能变了
  });
  connect(updater, &Updater::progressChanged, progressBar_, &QProgressBar::setValue);
  connect(updater, &Updater::finished, this,
          [this](const QString& result, int code, const QString& detail) {
            appendLog(QStringLiteral("升级结果 %1，错误码 %2 %3").arg(result).arg(code).arg(detail));
          });
  connect(updater, &Updater::alertRaised, this, [this](int code, const QString& detail) {
    appendLog(QStringLiteral("安全告警 %1：%2").arg(code).arg(detail));
  });
  connect(outbox, &EventOutbox::changed, this, &MainWindow::showOutbox);
  connect(demo, &DemoPanel::actionLogged, this, &MainWindow::appendLog);
}

void MainWindow::showOutbox() {
  outboxLabel_->setText(QStringLiteral("%1 条未确认（最新序号 %2，服务端已确认到 %3）")
                            .arg(outbox_->pendingCount())
                            .arg(outbox_->lastSeq())
                            .arg(outbox_->ackedSeq()));
}

void MainWindow::showFirmware() {
  const BootResult& boot = updater_->bootState();
  if (boot.hasFirmware) {
    firmwareLabel_->setText(QStringLiteral("%1（安全版本号 %2）")
                                .arg(boot.running.version)
                                .arg(boot.running.securityVersion));
  } else {
    firmwareLabel_->setText(QStringLiteral("恢复模式：没有可启动的固件，等待服务端推送"));
  }
  slotLabel_->setText(QStringLiteral("活动分区 %1，待确认分区 %2，最小安全版本号 %3")
                          .arg(boot.config.active,
                               boot.config.pending.isEmpty() ? QStringLiteral("无") : boot.config.pending)
                          .arg(boot.config.minSecurityVersion));
}

void MainWindow::appendLog(const QString& line) {
  log_->appendPlainText(
      QStringLiteral("%1  %2")
          .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), line));
}

}  // namespace fwds
