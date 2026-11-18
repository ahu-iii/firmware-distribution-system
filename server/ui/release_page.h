// ReleasePage：“灰度发布”页（设计第 6 节、4.2 节）。
//   上半部分  发布列表：发布号、固件、状态、金丝雀、目标设备的成功 / 失败 / 进行中计数、说明
//   下半部分  选中发布的目标设备：批次（金丝雀 / 全量）、状态、进度、说明
//   按钮      新建发布…、开始灰度、确认全量、暂停、继续、推送待确认设备、终止（操作员）；
//             紧急停止（操作员、维护员）
// 按钮只在当前状态允许时可点；能不能执行、互锁是否通过由 RolloutManager 裁决，
// 都只能经 AdminService 调用（再查一次角色，推送类操作再核对一次口令）。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"

class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;

namespace fwds {

class ReleasePage : public QWidget {
  Q_OBJECT
 public:
  ReleasePage(RolloutManager* rollout, FirmwareRepo* firmware, DeviceRegistry* registry,
              AdminService* admin, QWidget* parent = nullptr);

  // 登录账号变化后调用：按角色显示或隐藏按钮。
  void applyPermissions();

 private:
  void refresh();          // 重填发布列表（保持选中）和目标设备表
  void refreshTargets();   // 只重填目标设备表
  void updateButtons();    // 按选中发布的状态启用按钮
  qint64 selectedId() const;
  QString selectedState() const;

  void createRelease();
  // 需要二次确认的操作：弹出口令框，确认后调用 call。
  void confirmAndRun(const QString& title, const QString& text,
                     bool (AdminService::*call)(qint64, const SecureBuffer&, QString*));
  // 不需要口令的操作（暂停、紧急停止）。
  void runDirect(const QString& title, const QString& question,
                 bool (AdminService::*call)(qint64, QString*));

  RolloutManager* rollout_;
  FirmwareRepo* firmware_;
  DeviceRegistry* registry_;
  AdminService* admin_;

  QPushButton* createButton_;
  QPushButton* startButton_;
  QPushButton* fullButton_;
  QPushButton* pauseButton_;
  QPushButton* resumeButton_;
  QPushButton* heldButton_;
  QPushButton* terminateButton_;
  QPushButton* stopButton_;
  QTableWidget* releases_;
  QTableWidget* targets_;
  QLabel* targetsTitle_;
  QTimer* refreshTimer_;

 public:
  static constexpr int kRefreshCoalesceMs = 500;  // 进度引起的重填最多每 500 ms 一次
};

}  // namespace fwds
