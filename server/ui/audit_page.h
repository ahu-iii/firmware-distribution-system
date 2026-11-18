// AuditPage：“审计日志”页（设计第 6 节“日志与告警”、第 13 章），只有审计员能看到。
//   上方  分类筛选、刷新、“校验日志完整性”按钮；哈希链最新的序号和哈希（供审计员抄录，
//         下次核对时和检查点文件、和抄录的值对照）
//   表格  最近的审计日志：序号、时间、级别、分类、操作者、来源主机、设备、内容；WARN 行标红
// 读取和校验都经 AdminService，那里再检查一次角色。
#pragma once

#include <QWidget>

#include "server/business/admin_service.h"

class QComboBox;
class QLabel;
class QTableWidget;

namespace fwds {

class AuditPage : public QWidget {
  Q_OBJECT
 public:
  AuditPage(AuditService* audit, AdminService* admin, QWidget* parent = nullptr);

  // 切到本页、登录账号变化时调用：重新读取日志。
  void refresh();

 private:
  void verify();

  AuditService* audit_;
  AdminService* admin_;
  QComboBox* category_;
  QLabel* chainLabel_;
  QLabel* resultLabel_;
  QTableWidget* table_;
};

}  // namespace fwds
