// LogPage：“运行日志”页（设计第 6 节，用例 FT-16），所有角色都能看。
//   上方  筛选条件：设备、级别、模块、时间段（勾选后生效）、关键字；“查询”按钮
//   表格  符合条件的运行日志，从新到旧：时间（本机时间）、级别、模块、内容；WARN 及以上标红
//   下方  一共几条、是否只显示了最新的一部分、日志文件所在目录
// 页面只读日志文件，不写也不删；检索在 RunLogReader 里，这里只管界面。
#pragma once

#include <QWidget>

#include "common/log.h"
#include "server/business/device_registry.h"

class QCheckBox;
class QComboBox;
class QDateTimeEdit;
class QLabel;
class QLineEdit;
class QTableWidget;

namespace fwds {

class LogPage : public QWidget {
  Q_OBJECT
 public:
  // logFile 是服务端运行日志文件的目录和轮转规则，name 是文件名（不含 .log）。
  LogPage(DeviceRegistry* registry, const LogFileParams& logFile, const QString& name,
          QWidget* parent = nullptr);

  // 切到本页时调用：刷新设备下拉框，按当前条件重新查一次。
  void refresh();

 private:
  void search();
  void reloadDevices();

  DeviceRegistry* registry_;
  LogFileParams logFile_;
  QString name_;
  QComboBox* device_;
  QComboBox* level_;
  QComboBox* module_;
  QCheckBox* useTime_;
  QDateTimeEdit* from_;
  QDateTimeEdit* to_;
  QLineEdit* keyword_;
  QTableWidget* table_;
  QLabel* status_;
};

}  // namespace fwds
