// Database：服务端的 SQLite 数据库（设计 5.1 节），通过 Qt SQL 访问。
// 这里只负责打开文件和建表；每张表的读写在各自的模块里
// （设备表 → DeviceRegistry，账号表 → OperatorAuth，固件表 → FirmwareRepo，
// 发布表和发布目标表 → RolloutManager，审计日志表 → AuditService），SQL 一律用占位符绑定参数，不拼字符串。
// 数据库文件的位置来自配置 [server] db_file；*.db 已列入 .gitignore，不进仓库。
#pragma once

#include <QSqlDatabase>
#include <QString>

namespace fwds {

class Database {
 public:
  Database();
  ~Database();
  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;

  // 打开（不存在则创建）数据库并建表。path 为 ":memory:" 时建在内存里（单元测试用）。
  bool open(const QString& path, QString* error);

  // Qt SQL 的连接句柄，用来构造 QSqlQuery。
  QSqlDatabase handle() const;

 private:
  bool createSchema(QString* error);
  // 旧数据库的发布目标表升级到当前结构（status 增加 held）。
  bool upgradeReleaseTarget(QString* error);

  QString connectionName_;  // Qt SQL 按名字管理连接，每个 Database 对象用一个独立的名字
};

}  // namespace fwds
