#include "server/ui/main_window.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QVBoxLayout>

#include "server/net/tcp_server.h"
#include "server/ui/account_page.h"
#include "server/ui/audit_page.h"
#include "server/ui/device_page.h"
#include "server/ui/firmware_page.h"
#include "server/ui/login_dialog.h"
#include "server/ui/release_page.h"

namespace fwds {

MainWindow::MainWindow(TcpServer* server, DeviceRegistry* registry, AdminService* admin,
                       DispatchGate* gate, FirmwareRepo* firmware, RolloutManager* rollout,
                       AuditService* audit, QWidget* parent)
    : QMainWindow(parent), server_(server), registry_(registry), admin_(admin), gate_(gate) {
  setWindowTitle(QStringLiteral("固件分发服务端"));
  resize(1180, 640);

  // ---- 顶部一行 ----
  userLabel_ = new QLabel(this);
  dispatchBox_ = new QCheckBox(QStringLiteral("允许下发"), this);
  dispatchBox_->setToolTip(QStringLiteral("默认关闭（只监控）。只有维护员能打开，打开后操作员才能向设备推送固件"));
  dispatchLabel_ = new QLabel(this);
  auto* changePassword = new QPushButton(QStringLiteral("修改口令…"), this);
  auto* logout = new QPushButton(QStringLiteral("退出登录"), this);
  auto* top = new QHBoxLayout;
  top->addWidget(userLabel_);
  top->addStretch();
  top->addWidget(dispatchLabel_);
  top->addWidget(dispatchBox_);
  top->addSpacing(16);
  top->addWidget(changePassword);
  top->addWidget(logout);

  // ---- 页签 ----
  tabs_ = new QTabWidget(this);
  devicePage_ = new DevicePage(registry_, admin_, this);
  accountPage_ = new AccountPage(admin_, this);
  firmwarePage_ = new FirmwarePage(firmware, rollout, registry_, admin_, this);
  releasePage_ = new ReleasePage(rollout, firmware, registry_, admin_, this);
  auditPage_ = new AuditPage(audit, admin_, this);
  tabs_->addTab(devicePage_, QStringLiteral("设备监控"));
  tabs_->addTab(firmwarePage_, QStringLiteral("固件库"));
  tabs_->addTab(releasePage_, QStringLiteral("灰度发布"));

  auto* mainPage = new QWidget(this);
  auto* mainLayout = new QVBoxLayout(mainPage);
  mainLayout->addLayout(top);
  mainLayout->addWidget(tabs_);

  auto* lockedPage = new QLabel(QStringLiteral("尚未登录"), this);
  lockedPage->setAlignment(Qt::AlignCenter);

  stack_ = new QStackedWidget(this);
  stack_->addWidget(lockedPage);
  stack_->addWidget(mainPage);
  setCentralWidget(stack_);

  summary_ = new QLabel(this);
  statusBar()->addWidget(summary_);

  // 用 clicked 而不是 toggled：只响应人点的那一下，程序里同步勾选状态时不会再触发
  connect(dispatchBox_, &QCheckBox::clicked, this, &MainWindow::onDispatchClicked);
  connect(gate_, &DispatchGate::changed, this, &MainWindow::updateDispatchLabel);
  connect(changePassword, &QPushButton::clicked, this, [this]() {
    ChangePasswordDialog dialog(admin_, false, this);
    dialog.exec();
    if (!admin_->loggedIn()) promptLogin();  // 原口令多次输错被锁定并退出了登录
  });
  connect(logout, &QPushButton::clicked, this, [this]() {
    admin_->logout();
    promptLogin();
  });
  // 切到“账号管理”“审计日志”页时重新读一次（锁定状态、新的日志随时会变）
  connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) {
    if (tabs_->widget(index) == accountPage_) accountPage_->refresh();
    if (tabs_->widget(index) == auditPage_) auditPage_->refresh();
  });
  connect(admin_, &AdminService::sessionChanged, this, &MainWindow::applySession);
  connect(registry_, &DeviceRegistry::deviceChanged, this, &MainWindow::updateSummary);
  connect(registry_, &DeviceRegistry::deviceAdded, this, &MainWindow::updateSummary);
  connect(server_, &TcpServer::sessionOpened, this, &MainWindow::updateSummary);
  // sessionClosed 发出时 TcpServer 已经把这条连接从列表里去掉了
  connect(server_, &TcpServer::sessionClosed, this, &MainWindow::updateSummary);

  applySession();
  updateDispatchLabel();
  updateSummary();
}

void MainWindow::promptLogin() {
  stack_->setCurrentIndex(0);
  LoginDialog login(admin_, this);
  if (login.exec() != QDialog::Accepted) {
    close();  // 最后一个窗口关闭，程序退出
    return;
  }
  // 新建账号或口令被重置过：先改口令，不改就退回登录
  if (admin_->mustChangePassword()) {
    ChangePasswordDialog change(admin_, true, this);
    if (change.exec() != QDialog::Accepted) {
      admin_->logout();
      promptLogin();
      return;
    }
  }
  applySession();
}

void MainWindow::applySession() {
  // 还需要先改口令的账号不算登录完成，界面保持锁定
  const bool ready = admin_->loggedIn() && !admin_->mustChangePassword();
  stack_->setCurrentIndex(ready ? 1 : 0);
  if (!ready) return;

  const OperatorAccount& user = admin_->current();
  userLabel_->setText(
      QStringLiteral("当前账号：%1（%2）").arg(user.username, roleDisplayName(user.role)));

  // 按角色显示功能入口（第一道权限检查；第二道在 AdminService 里）
  dispatchBox_->setEnabled(admin_->can(Permission::ToggleDispatch));
  devicePage_->applyPermissions();
  firmwarePage_->applyPermissions();
  releasePage_->applyPermissions();
  const int accountTab = tabs_->indexOf(accountPage_);
  if (admin_->can(Permission::ManageAccounts)) {
    if (accountTab < 0) tabs_->addTab(accountPage_, QStringLiteral("账号管理"));
    accountPage_->refresh();
  } else if (accountTab >= 0) {
    tabs_->removeTab(accountTab);
  }
  const int auditTab = tabs_->indexOf(auditPage_);
  if (admin_->can(Permission::ViewAudit)) {
    if (auditTab < 0) tabs_->addTab(auditPage_, QStringLiteral("审计日志"));
    auditPage_->refresh();
  } else if (auditTab >= 0) {
    tabs_->removeTab(auditTab);
  }
}

void MainWindow::onDispatchClicked(bool checked) {
  if (checked) {
    const auto answer = QMessageBox::question(
        this, QStringLiteral("允许下发"),
        QStringLiteral("打开后，操作员可以向现场设备推送固件。确认打开？"));
    if (answer != QMessageBox::Yes) {
      updateDispatchLabel();
      return;
    }
  }
  QString error;
  if (!admin_->setDispatchEnabled(checked, &error)) {
    QMessageBox::warning(this, QStringLiteral("允许下发"), error);
  }
  updateDispatchLabel();  // 无论成功与否，勾选状态都以 DispatchGate 的实际状态为准
}

void MainWindow::updateDispatchLabel() {
  dispatchBox_->setChecked(gate_->enabled());
  dispatchLabel_->setText(gate_->enabled() ? QStringLiteral("当前：允许下发")
                                           : QStringLiteral("当前：只监控"));
  dispatchLabel_->setStyleSheet(gate_->enabled() ? QStringLiteral("color: #b26a00; font-weight: bold;")
                                                 : QStringLiteral("color: #1b7f3b;"));
}

void MainWindow::updateSummary() {
  summary_->setText(QStringLiteral("监听 %1:%2　｜　设备：在线 %3 / 已注册 %4　｜　当前连接 %5")
                        .arg(server_->serverAddress().toString())
                        .arg(server_->serverPort())
                        .arg(registry_->onlineCount())
                        .arg(registry_->devices().size())
                        .arg(server_->sessions().size()));
}

}  // namespace fwds
