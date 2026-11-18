#include "server/ui/login_dialog.h"

#include <QApplication>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace fwds {

namespace {

QLineEdit* newPasswordEdit(QWidget* parent) {
  auto* edit = new QLineEdit(parent);
  edit->setEchoMode(QLineEdit::Password);  // 输入不回显
  edit->setMaxLength(kPwdMaxLength);
  return edit;
}

QLabel* newMessageLabel(QWidget* parent) {
  auto* label = new QLabel(parent);
  label->setWordWrap(true);
  label->setStyleSheet(QStringLiteral("color: #b00020;"));
  return label;
}

}  // namespace

SecureBuffer takePassword(QLineEdit* edit) {
  SecureBuffer password = passwordFromString(edit->text());
  edit->clear();
  return password;
}

bool askConfirmPassword(QWidget* parent, const QString& title, const QString& text,
                        SecureBuffer* password) {
  QDialog dialog(parent);
  dialog.setWindowTitle(title);
  dialog.setMinimumWidth(420);
  auto* description = new QLabel(text, &dialog);
  description->setWordWrap(true);
  auto* edit = newPasswordEdit(&dialog);
  auto* form = new QFormLayout;
  form->addRow(QStringLiteral("当前账号口令"), edit);
  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("确认执行"));
  buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  auto* layout = new QVBoxLayout(&dialog);
  layout->addWidget(description);
  layout->addLayout(form);
  layout->addWidget(buttons);
  QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  const bool accepted = dialog.exec() == QDialog::Accepted;
  *password = takePassword(edit);  // 无论确认与否都从输入框取走并清空
  return accepted;
}

// ---------- LoginDialog ----------

LoginDialog::LoginDialog(AdminService* admin, QWidget* parent)
    : QDialog(parent), admin_(admin), bootstrap_(admin->needsBootstrap()) {
  setWindowTitle(bootstrap_ ? QStringLiteral("首次运行：创建维护员账号")
                            : QStringLiteral("登录固件分发服务端"));
  setMinimumWidth(380);

  auto* layout = new QVBoxLayout(this);
  if (bootstrap_) {
    auto* hint = new QLabel(
        QStringLiteral("系统里还没有任何账号。请先创建一个维护员账号，其他账号登录后由维护员创建。\n"
                       "口令要求：至少 %1 个字符，同时包含字母和数字。")
            .arg(kPwdMinLength),
        this);
    hint->setWordWrap(true);
    layout->addWidget(hint);
  }

  auto* form = new QFormLayout;
  username_ = new QLineEdit(this);
  username_->setMaxLength(32);
  password_ = newPasswordEdit(this);
  form->addRow(QStringLiteral("账号"), username_);
  form->addRow(QStringLiteral("口令"), password_);
  if (bootstrap_) {
    confirm_ = newPasswordEdit(this);
    form->addRow(QStringLiteral("再输一遍"), confirm_);
  }
  layout->addLayout(form);

  message_ = newMessageLabel(this);
  layout->addWidget(message_);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  buttons->button(QDialogButtonBox::Ok)->setText(bootstrap_ ? QStringLiteral("创建并登录")
                                                            : QStringLiteral("登录"));
  buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("退出程序"));
  layout->addWidget(buttons);
  connect(buttons, &QDialogButtonBox::accepted, this, &LoginDialog::submit);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void LoginDialog::submit() {
  const QString username = username_->text().trimmed();
  SecureBuffer password = takePassword(password_);
  QString message;

  if (bootstrap_) {
    const SecureBuffer again = takePassword(confirm_);
    if (!samePassword(password, again)) {
      message_->setText(QStringLiteral("两次输入的口令不一致"));
      return;
    }
    if (!admin_->bootstrapMaintainer(username, password, &message)) {
      message_->setText(message);
      return;
    }
  }

  // 口令派生要算几十万次哈希，会停顿零点几秒，换成等待光标提示一下
  QApplication::setOverrideCursor(Qt::WaitCursor);
  const AuthResult result = admin_->login(username, password, &message);
  QApplication::restoreOverrideCursor();
  if (result != AuthResult::Ok) {
    message_->setText(message);
    password_->setFocus();
    return;
  }
  accept();
}

// ---------- ChangePasswordDialog ----------

ChangePasswordDialog::ChangePasswordDialog(AdminService* admin, bool forced, QWidget* parent)
    : QDialog(parent), admin_(admin) {
  setWindowTitle(QStringLiteral("修改口令"));
  setMinimumWidth(380);

  auto* layout = new QVBoxLayout(this);
  auto* hint = new QLabel(
      (forced ? QStringLiteral("这是初始口令或被重置过的口令，必须先修改才能继续使用。\n") : QString()) +
          QStringLiteral("口令要求：至少 %1 个字符，同时包含字母和数字。").arg(kPwdMinLength),
      this);
  hint->setWordWrap(true);
  layout->addWidget(hint);

  auto* form = new QFormLayout;
  oldPassword_ = newPasswordEdit(this);
  newPassword_ = newPasswordEdit(this);
  confirm_ = newPasswordEdit(this);
  form->addRow(QStringLiteral("原口令"), oldPassword_);
  form->addRow(QStringLiteral("新口令"), newPassword_);
  form->addRow(QStringLiteral("再输一遍"), confirm_);
  layout->addLayout(form);

  message_ = newMessageLabel(this);
  layout->addWidget(message_);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("修改"));
  buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  layout->addWidget(buttons);
  connect(buttons, &QDialogButtonBox::accepted, this, &ChangePasswordDialog::submit);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

void ChangePasswordDialog::submit() {
  const SecureBuffer oldPassword = takePassword(oldPassword_);
  const SecureBuffer newPassword = takePassword(newPassword_);
  const SecureBuffer again = takePassword(confirm_);
  if (!samePassword(newPassword, again)) {
    message_->setText(QStringLiteral("两次输入的新口令不一致"));
    return;
  }
  QString error;
  QApplication::setOverrideCursor(Qt::WaitCursor);
  const bool ok = admin_->changeOwnPassword(oldPassword, newPassword, &error);
  QApplication::restoreOverrideCursor();
  if (!ok) {
    message_->setText(error);
    // 原口令连续输错会锁定账号并退出登录，这时对话框没有继续的意义
    if (!admin_->loggedIn()) reject();
    return;
  }
  accept();
}

}  // namespace fwds
