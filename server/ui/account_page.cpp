#include "server/ui/account_page.h"

#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "server/ui/login_dialog.h"

namespace fwds {

namespace {

enum Column { ColUsername, ColRole, ColFailed, ColLocked, ColMustChange, ColCount };

// 让维护员输入一个初始口令（输两遍）。取消返回 false。
bool askInitialPassword(QWidget* parent, const QString& title, QComboBox* roleBox,
                        QLineEdit* usernameEdit, SecureBuffer* password) {
  QDialog dialog(parent);
  dialog.setWindowTitle(title);
  dialog.setMinimumWidth(400);
  auto* form = new QFormLayout(&dialog);
  auto* hint = new QLabel(
      QStringLiteral("初始口令至少 %1 个字符，同时包含字母和数字。\n对方第一次登录时必须先改掉它。")
          .arg(kPwdMinLength),
      &dialog);
  form->addRow(hint);
  if (usernameEdit) form->addRow(QStringLiteral("账号"), usernameEdit);
  if (roleBox) form->addRow(QStringLiteral("角色"), roleBox);
  auto* first = new QLineEdit(&dialog);
  auto* second = new QLineEdit(&dialog);
  first->setEchoMode(QLineEdit::Password);
  second->setEchoMode(QLineEdit::Password);
  first->setMaxLength(kPwdMaxLength);
  second->setMaxLength(kPwdMaxLength);
  form->addRow(QStringLiteral("初始口令"), first);
  form->addRow(QStringLiteral("再输一遍"), second);
  auto* box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  box->button(QDialogButtonBox::Ok)->setText(QStringLiteral("确定"));
  box->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  form->addRow(box);
  QObject::connect(box, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  QObject::connect(box, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

  const bool accepted = dialog.exec() == QDialog::Accepted;
  // 输入框是对话框的子对象，马上就要销毁；先把口令取走并清空
  if (usernameEdit) usernameEdit->setParent(nullptr);
  if (roleBox) roleBox->setParent(nullptr);
  SecureBuffer a = takePassword(first);
  const SecureBuffer b = takePassword(second);
  if (!accepted) return false;
  if (!samePassword(a, b)) {
    QMessageBox::warning(parent, title, QStringLiteral("两次输入的口令不一致"));
    return false;
  }
  *password = std::move(a);
  return true;
}

}  // namespace

AccountPage::AccountPage(AdminService* admin, QWidget* parent) : QWidget(parent), admin_(admin) {
  auto* createButton = new QPushButton(QStringLiteral("新建账号…"), this);
  resetButton_ = new QPushButton(QStringLiteral("重置口令…"), this);
  unlockButton_ = new QPushButton(QStringLiteral("解锁"), this);
  removeButton_ = new QPushButton(QStringLiteral("删除"), this);
  auto* buttons = new QHBoxLayout;
  buttons->addWidget(createButton);
  buttons->addWidget(resetButton_);
  buttons->addWidget(unlockButton_);
  buttons->addWidget(removeButton_);
  buttons->addStretch();

  table_ = new QTableWidget(0, ColCount, this);
  table_->setHorizontalHeaderLabels({QStringLiteral("账号"), QStringLiteral("角色"),
                                     QStringLiteral("连续失败次数"), QStringLiteral("锁定至"),
                                     QStringLiteral("须改口令")});
  table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  table_->verticalHeader()->setVisible(false);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(buttons);
  layout->addWidget(table_);

  connect(createButton, &QPushButton::clicked, this, &AccountPage::createAccount);
  connect(resetButton_, &QPushButton::clicked, this, &AccountPage::resetPassword);
  connect(unlockButton_, &QPushButton::clicked, this, &AccountPage::unlockAccount);
  connect(removeButton_, &QPushButton::clicked, this, &AccountPage::removeAccount);
  connect(table_, &QTableWidget::itemSelectionChanged, this, &AccountPage::updateButtons);
  updateButtons();
}

void AccountPage::refresh() {
  QList<OperatorAccount> accounts;
  QString error;
  table_->setRowCount(0);
  if (!admin_->listAccounts(&accounts, &error)) return;  // 不是维护员：表保持为空
  for (const OperatorAccount& a : accounts) {
    const int row = table_->rowCount();
    table_->insertRow(row);
    const bool locked = a.lockedUntil.isValid() && QDateTime::currentDateTimeUtc() < a.lockedUntil;
    table_->setItem(row, ColUsername, new QTableWidgetItem(a.username));
    table_->setItem(row, ColRole, new QTableWidgetItem(roleDisplayName(a.role)));
    table_->setItem(row, ColFailed, new QTableWidgetItem(QString::number(a.failedCount)));
    table_->setItem(row, ColLocked,
                    new QTableWidgetItem(locked ? a.lockedUntil.toLocalTime().toString(
                                                      QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                                                : QStringLiteral("—")));
    table_->setItem(row, ColMustChange,
                    new QTableWidgetItem(a.mustChange ? QStringLiteral("是") : QStringLiteral("否")));
  }
  updateButtons();
}

QString AccountPage::selectedUsername() const {
  const int row = table_->currentRow();
  if (row < 0 || table_->selectedItems().isEmpty()) return QString();
  return table_->item(row, ColUsername)->text();
}

void AccountPage::updateButtons() {
  const bool selected = !selectedUsername().isEmpty();
  resetButton_->setEnabled(selected);
  unlockButton_->setEnabled(selected);
  removeButton_->setEnabled(selected);
}

void AccountPage::createAccount() {
  auto* usernameEdit = new QLineEdit;
  usernameEdit->setMaxLength(32);
  auto* roleBox = new QComboBox;
  for (const Role role : {Role::Operator, Role::Maintainer, Role::Auditor}) {
    roleBox->addItem(roleDisplayName(role), static_cast<int>(role));
  }
  SecureBuffer password;
  const bool accepted =
      askInitialPassword(this, QStringLiteral("新建账号"), roleBox, usernameEdit, &password);
  const QString username = usernameEdit->text().trimmed();
  const Role role = static_cast<Role>(roleBox->currentData().toInt());
  delete usernameEdit;
  delete roleBox;
  if (!accepted) return;

  QString error;
  QApplication::setOverrideCursor(Qt::WaitCursor);
  const bool ok = admin_->createAccount(username, role, password, &error);
  QApplication::restoreOverrideCursor();
  if (!ok) QMessageBox::warning(this, QStringLiteral("新建账号"), error);
  refresh();
}

void AccountPage::resetPassword() {
  const QString username = selectedUsername();
  if (username.isEmpty()) return;
  SecureBuffer password;
  if (!askInitialPassword(this, QStringLiteral("重置 %1 的口令").arg(username), nullptr, nullptr,
                          &password)) {
    return;
  }
  QString error;
  QApplication::setOverrideCursor(Qt::WaitCursor);
  const bool ok = admin_->resetPassword(username, password, &error);
  QApplication::restoreOverrideCursor();
  if (!ok) QMessageBox::warning(this, QStringLiteral("重置口令"), error);
  refresh();
}

void AccountPage::unlockAccount() {
  const QString username = selectedUsername();
  if (username.isEmpty()) return;
  QString error;
  if (!admin_->unlockAccount(username, &error)) {
    QMessageBox::warning(this, QStringLiteral("解锁"), error);
  }
  refresh();
}

void AccountPage::removeAccount() {
  const QString username = selectedUsername();
  if (username.isEmpty()) return;
  const auto answer = QMessageBox::question(this, QStringLiteral("删除账号"),
                                            QStringLiteral("删除账号 %1？").arg(username));
  if (answer != QMessageBox::Yes) return;
  QString error;
  if (!admin_->removeAccount(username, &error)) {
    QMessageBox::warning(this, QStringLiteral("删除账号"), error);
  }
  refresh();
}

}  // namespace fwds
