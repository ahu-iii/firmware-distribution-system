// FirmwarePage：“固件库”页（设计第 6 节）。
//   上半部分  固件列表；选中一行，右边显示它的 manifest 内容和服务端的检查结果
//   下半部分  下发记录（发布号、时间、设备、固件、操作人、状态）
//   按钮      导入固件包…（维护员）、下发到设备…（操作员）
// 界面只负责选文件、选设备和显示结果：验签和入库在 FirmwareRepo，能不能下发由 RolloutManager 裁决，
// 两者都只能经 AdminService 调用，那里会再检查一次角色。
// 完整的灰度发布（按分组、观察期、确认全量、紧急停止）在“灰度发布”页。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"

class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;
class QTimer;

namespace fwds {

class FirmwarePage : public QWidget {
  Q_OBJECT
 public:
  FirmwarePage(FirmwareRepo* firmware, RolloutManager* rollout, DeviceRegistry* registry,
               AdminService* admin, QWidget* parent = nullptr);

  // 登录账号变化后调用：按角色显示或隐藏按钮。
  void applyPermissions();

 private:
  void refreshFirmware();    // 固件库有变化时重填固件列表
  void refreshDispatches();  // 有新的下发时重填下发记录
  void showDetail();         // 选中行变化时刷新右边的详情
  void importPackage();
  void dispatchSelected();
  QString selectedPkgId() const;

  FirmwareRepo* firmware_;
  RolloutManager* rollout_;
  DeviceRegistry* registry_;
  AdminService* admin_;

  QPushButton* importButton_;
  QPushButton* dispatchButton_;
  QTableWidget* table_;
  QTextEdit* detail_;
  QTableWidget* dispatches_;
  QTimer* dispatchTimer_;

 public:
  static constexpr int kRefreshCoalesceMs = 500;
};

}  // namespace fwds
