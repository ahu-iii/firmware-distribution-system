// 登录相关的两个对话框（设计第 6 节“登录”页）：
//   LoginDialog          输入账号、口令登录；账号表为空（首次运行）时改为创建第一个维护员
//   ChangePasswordDialog 修改自己的口令；新建或被重置的账号登录后强制弹出
//   askConfirmPassword   推送固件之类的操作执行前，重新输入口令确认
// 对话框只收集输入，校验和存储都在 AdminService / OperatorAuth 里。
// 口令从输入框取出后放进 SecureBuffer，输入框立即清空。
#pragma once

#include <QDialog>

#include "server/business/admin_service.h"

class QLabel;
class QLineEdit;

namespace fwds {

class LoginDialog : public QDialog {
  Q_OBJECT
 public:
  explicit LoginDialog(AdminService* admin, QWidget* parent = nullptr);

 private:
  void submit();

  AdminService* admin_;
  bool bootstrap_;  // true：首次运行，创建维护员
  QLineEdit* username_;
  QLineEdit* password_;
  QLineEdit* confirm_ = nullptr;  // 只有创建账号时才有“再输一遍”
  QLabel* message_;
};

class ChangePasswordDialog : public QDialog {
  Q_OBJECT
 public:
  // forced 为 true 时提示“必须先修改初始口令”。
  ChangePasswordDialog(AdminService* admin, bool forced, QWidget* parent = nullptr);

 private:
  void submit();

  AdminService* admin_;
  QLineEdit* oldPassword_;
  QLineEdit* newPassword_;
  QLineEdit* confirm_;
  QLabel* message_;
};

// 取出输入框里的口令并清空输入框。
SecureBuffer takePassword(QLineEdit* edit);

// 二次确认（设计 4.2 节）：显示将要执行的操作，要求重新输入当前账号的口令。
// 点“确认执行”返回 true 并把口令放进 password；取消返回 false。口令对不对由 AdminService 核对。
bool askConfirmPassword(QWidget* parent, const QString& title, const QString& text,
                        SecureBuffer* password);

}  // namespace fwds
