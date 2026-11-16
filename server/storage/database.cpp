#include "server/storage/database.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>

namespace fwds {

namespace {

// 建表语句，字段与设计 5.1 节的 ER 图一致。时间一律存 UTC 的 ISO 8601 文本。
// 固件、发布、事件、审计几张表在对应模块实现时加入。
const char* const kSchema[] = {
    // 账号表：不存口令，只存派生函数名、迭代次数、盐和派生结果（设计 11.2 节）
    "CREATE TABLE IF NOT EXISTS operator ("
    "  username     TEXT PRIMARY KEY,"
    "  role         TEXT NOT NULL CHECK (role IN ('operator','maintainer','auditor')),"
    "  kdf          TEXT NOT NULL,"
    "  kdf_iter     INTEGER NOT NULL,"
    "  salt         BLOB NOT NULL,"
    "  pwd_hash     BLOB NOT NULL,"
    "  failed_count INTEGER NOT NULL DEFAULT 0,"
    "  locked_until TEXT,"
    "  must_change  INTEGER NOT NULL DEFAULT 0"
    ")",
    // 设备表：注册时绑定证书指纹，登录时比对
    "CREATE TABLE IF NOT EXISTS device ("
    "  device_id        TEXT PRIMARY KEY,"
    "  model            TEXT NOT NULL,"
    "  group_tag        TEXT NOT NULL DEFAULT '',"
    "  status           TEXT NOT NULL CHECK (status IN ('active','disabled')),"
    "  cert_fingerprint TEXT NOT NULL,"
    "  cert_not_after   TEXT NOT NULL,"
    "  current_version  TEXT NOT NULL DEFAULT '',"
    "  security_version INTEGER NOT NULL DEFAULT 0,"
    "  online_state     TEXT NOT NULL DEFAULT 'offline',"
    "  last_heartbeat   TEXT,"
    "  event_ack        INTEGER NOT NULL DEFAULT 0"
    ")",
};

}  // namespace

Database::Database()
    : connectionName_(QStringLiteral("fwds-") + QUuid::createUuid().toString(QUuid::WithoutBraces)) {}

Database::~Database() {
  if (QSqlDatabase::contains(connectionName_)) {
    QSqlDatabase::database(connectionName_).close();
    QSqlDatabase::removeDatabase(connectionName_);
  }
}

QSqlDatabase Database::handle() const { return QSqlDatabase::database(connectionName_); }

bool Database::open(const QString& path, QString* error) {
  const bool inMemory = path == QLatin1String(":memory:");
  // 数据库所在目录不存在时先建出来（SQLite 只会建文件，不会建目录）
  if (!inMemory && !QDir().mkpath(QFileInfo(path).absolutePath())) {
    *error = QStringLiteral("无法创建数据库所在目录：%1").arg(path);
    return false;
  }
  QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName_);
  db.setDatabaseName(path);
  if (!db.open()) {
    *error = QStringLiteral("打不开数据库 %1：%2").arg(path, db.lastError().text());
    return false;
  }
  // 数据库里有口令派生值和设备指纹，文件只允许运行账户读写
  if (!inMemory) {
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
  }
  // synchronous=FULL：每次提交都刷盘，断电不丢已提交的数据
  QSqlQuery pragma(db);
  if (!pragma.exec(QStringLiteral("PRAGMA synchronous=FULL"))) {
    *error = QStringLiteral("数据库初始化失败：%1").arg(pragma.lastError().text());
    return false;
  }
  return createSchema(error);
}

bool Database::createSchema(QString* error) {
  QSqlQuery query(handle());
  for (const char* sql : kSchema) {
    if (!query.exec(QString::fromLatin1(sql))) {
      *error = QStringLiteral("建表失败：%1").arg(query.lastError().text());
      return false;
    }
  }
  return true;
}

}  // namespace fwds
