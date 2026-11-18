// 服务端主窗口（设计第 6 节）。
//   顶部一行：当前账号与角色、“允许下发”开关、修改口令、退出登录
//   页签：    设备监控、固件库、灰度发布（所有角色，按钮按角色显示）、
//             账号管理（仅维护员）、审计日志（仅审计员）
// 没登录时窗口只显示一句提示，登录对话框盖在上面；登录后按角色显示可用功能。
// UI 层只通过业务层的对象和信号槽拿数据，不碰 socket，不直接读写数据库。
#pragma once

#include <QMainWindow>

#include "server/business/admin_service.h"

class QCheckBox;
class QLabel;
class QPushButton;
class QStackedWidget;
class QTabWidget;

namespace fwds {

class AccountPage;
class AuditPage;
class DevicePage;
class FirmwarePage;
class ReleasePage;
class TcpServer;

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  MainWindow(TcpServer* server, DeviceRegistry* registry, AdminService* admin, DispatchGate* gate,
             FirmwareRepo* firmware, RolloutManager* rollout, AuditService* audit,
             QWidget* parent = nullptr);

  // 弹出登录对话框。登录成功显示主界面；用户取消则关闭窗口、退出程序。
  void promptLogin();

 private:
  void applySession();          // 登录状态或角色变化后刷新界面
  void onDispatchClicked(bool checked);
  void updateDispatchLabel();
  void updateSummary();

  TcpServer* server_;
  DeviceRegistry* registry_;
  AdminService* admin_;
  DispatchGate* gate_;

  QStackedWidget* stack_;   // 第 0 页：未登录提示；第 1 页：主界面
  QTabWidget* tabs_;
  DevicePage* devicePage_;
  FirmwarePage* firmwarePage_;
  ReleasePage* releasePage_;
  AccountPage* accountPage_;
  AuditPage* auditPage_;
  QLabel* userLabel_;
  QCheckBox* dispatchBox_;
  QLabel* dispatchLabel_;
  QLabel* summary_;
};

}  // namespace fwds
