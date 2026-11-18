// 设备事件对话框：在设备监控页选中一台设备后打开，按序号列出它最近上报的事件，
// 顶部一行说明对账情况——已连续确认到哪个序号、有没有暂存着等补齐的事件（设计 4.6 节）。
#pragma once

#include <QDialog>

#include "server/business/event_store.h"

class QLabel;
class QTableWidget;

namespace fwds {

class EventDialog : public QDialog {
  Q_OBJECT
 public:
  EventDialog(EventStore* events, const QString& deviceId, QWidget* parent = nullptr);

 private:
  void reload();

  EventStore* events_;
  QString deviceId_;
  QLabel* summary_;
  QTableWidget* table_;
};

}  // namespace fwds
