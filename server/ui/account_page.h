// AccountPage：“账号管理”页，只有维护员能看到（设计 11.1 节）。
// 新建账号、重置口令、解锁、删除，全部通过 AdminService，那里会再检查一次角色。
// 表格里只有账号名、角色、失败次数、锁定时间；盐和口令派生值不会被读到界面上。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"

class QPushButton;
class QTableWidget;

namespace fwds {

class AccountPage : public QWidget {
  Q_OBJECT
 public:
  explicit AccountPage(AdminService* admin, QWidget* parent = nullptr);

  // 重新读取账号列表。
  void refresh();

 private:
  void createAccount();
  void resetPassword();
  void unlockAccount();
  void removeAccount();
  QString selectedUsername() const;
  void updateButtons();

  AdminService* admin_;
  QTableWidget* table_;
  QPushButton* resetButton_;
  QPushButton* unlockButton_;
  QPushButton* removeButton_;
};

}  // namespace fwds
