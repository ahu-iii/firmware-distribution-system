// Database：服务端的 SQLite 数据库（设计 5.1 节），通过 Qt SQL 访问。
// 这里只负责打开文件和建表；每张表的读写在各自的模块里
// （设备表 → DeviceRegistry，账号表 → OperatorAuth，固件表 → FirmwareRepo，
// 发布表和发布目标表 → RolloutManager，审计日志表 → AuditService），SQL 一律用占位符绑定参数，不拼字符串。
// 数据库文件的位置来自配置 [server] db_file；*.db 已列入 .gitignore，不进仓库。
#pragma once

#include <QSqlDatabase>
#include <QString>

namespace fwds {

// 数据库结构版本，存在 SQLite 的 PRAGMA user_version 里（设计 8.4 节“版本标识”）。
// 改了表结构就加 1，并在 open() 里写好从旧版本迁移的步骤。
//   1：最初的结构（这个编号出现之前建的库，user_version 是 0，按 1 处理）
//   2：release_target.status 增加 held
inline constexpr int kSchemaVersion = 2;

class Database {
 public:
  Database();
  ~Database();
  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;

  // 打开（不存在则创建）数据库，建表并把旧结构迁移到 kSchemaVersion。
  // 数据库的结构版本比本程序新（回滚到旧程序却没有恢复数据库备份）时拒绝打开，不去动它。
  // path 为 ":memory:" 时建在内存里（单元测试用）。
  bool open(const QString& path, QString* error);

  // 当前数据库的结构版本（open 成功后等于 kSchemaVersion）。
  int schemaVersion() const;

  // Qt SQL 的连接句柄，用来构造 QSqlQuery。
  QSqlDatabase handle() const;

 private:
  bool createSchema(QString* error);
  // 旧数据库的发布目标表升级到当前结构（status 增加 held）。
  bool upgradeReleaseTarget(QString* error);

  QString connectionName_;  // Qt SQL 按名字管理连接，每个 Database 对象用一个独立的名字
};

}  // namespace fwds
