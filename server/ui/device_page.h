// DevicePage：“设备监控”页（设计第 6 节）。上半部分是设备表，下半部分是安全告警与操作记录。
// 所有角色都能打开选中设备的事件列表（只读）。
// 维护员多三个按钮：注册设备、停用 / 启用、修改分组；其他角色看不到这些入口，
// 就算绕过界面去调 AdminService，那里还会再检查一次角色。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"
#include "server/business/event_store.h"

class QListWidget;
class QPushButton;
class QTableView;
class QTimer;

namespace fwds {

class DeviceTableModel;

class DevicePage : public QWidget {
  Q_OBJECT
 public:
  // 设备表变化后多久按内容重新调整一次列宽（毫秒）
  static constexpr int kColumnFitIntervalMs = 1000;

  DevicePage(DeviceRegistry* registry, AdminService* admin, QWidget* parent = nullptr);

  // 登录账号变化后调用：按角色显示或隐藏管理按钮。
  void applyPermissions();

  // 事件入库模块，设置后“设备事件”按钮可用。
  void setEventStore(EventStore* events);

 private:
  void registerDevice();
  void toggleDisabled();
  void changeGroup();
  void showEvents();
  void updateButtons();
  QString selectedDeviceId() const;
  void appendEvent(const QString& time, bool alert, const QString& text);

  DeviceRegistry* registry_;
  AdminService* admin_;
  DeviceTableModel* model_;
  QTableView* table_;
  QTimer* fitTimer_;  // 列宽调整的合并定时器
  QListWidget* events_;
  QPushButton* registerButton_;
  QPushButton* disableButton_;
  QPushButton* groupButton_;
  QPushButton* eventsButton_;
  EventStore* eventStore_ = nullptr;
};

}  // namespace fwds
