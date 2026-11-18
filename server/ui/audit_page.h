// AuditPage：“审计日志”页（设计第 6 节“日志与告警”、第 13 章），只有审计员能看到。
//   上方  检索条件：分类、设备、时间段（勾选后生效）、关键字；“查询”和“校验日志完整性”按钮；
//         哈希链最新的序号和哈希（供审计员抄录，下次核对时和检查点文件、和抄录的值对照）
//   表格  符合条件的审计日志，从新到旧：序号、时间、级别、分类、操作者、来源主机、设备、内容；WARN 行标红
//   下方  找到几条、是否只显示了最新的一部分
// 检索只筛选显示哪些行；“校验日志完整性”始终从第一行开始校验整张表，和检索条件无关。
// 读取和校验都经 AdminService，那里再检查一次角色。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"

class QCheckBox;
class QComboBox;
class QDateTimeEdit;
class QLabel;
class QLineEdit;
class QTableWidget;

namespace fwds {

class AuditPage : public QWidget {
  Q_OBJECT
 public:
  AuditPage(AuditService* audit, AdminService* admin, QWidget* parent = nullptr);

  // 切到本页、登录账号变化时调用：按当前条件重新查一次。
  void refresh();

 private:
  void verify();
  // 在表格里选中序号为 id 的行；不在当前结果里返回 false。
  bool selectEntry(qint64 id);

  AuditService* audit_;
  AdminService* admin_;
  QComboBox* category_;
  QLineEdit* device_;
  QCheckBox* useTime_;
  QDateTimeEdit* from_;
  QDateTimeEdit* to_;
  QLineEdit* keyword_;
  QLabel* chainLabel_;
  QLabel* resultLabel_;
  QTableWidget* table_;
  QLabel* status_;
};

}  // namespace fwds
