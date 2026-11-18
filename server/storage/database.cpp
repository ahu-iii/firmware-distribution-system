#include "server/storage/database.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>

namespace fwds {

namespace {

// 发布目标表：发布里的每台设备一行。phase 是它属于灰度批还是全量批，status 是它自己的结果。
// held（待确认）：轮到它时不在线或正忙，没有推送，要操作员确认后才推（断网不盲发）
const char kReleaseTargetTable[] =
    "CREATE TABLE IF NOT EXISTS release_target ("
    "  release_id INTEGER NOT NULL REFERENCES \"release\"(release_id),"
    "  device_id  TEXT NOT NULL REFERENCES device(device_id),"
    "  phase      TEXT NOT NULL CHECK (phase IN ('canary','full')),"
    "  status     TEXT NOT NULL CHECK (status IN ('pending','held','notified','success','failed',"
    "                                             'rolled_back','cancelled')),"
    "  progress   INTEGER NOT NULL DEFAULT 0,"
    "  last_error TEXT NOT NULL DEFAULT '',"
    "  updated_at TEXT NOT NULL,"
    "  PRIMARY KEY (release_id, device_id)"
    ")";

// 建表语句，字段与设计 5.1 节的 ER 图一致。时间一律存 UTC 的 ISO 8601 文本。
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
    // 固件表：只登记通过了整包检查的固件包。file_path 是固件库目录下的文件名（包 ID.fwpkg）
    "CREATE TABLE IF NOT EXISTS firmware ("
    "  pkg_id           TEXT PRIMARY KEY,"
    "  model            TEXT NOT NULL,"
    "  version          TEXT NOT NULL,"
    "  security_version INTEGER NOT NULL,"
    "  image_size       INTEGER NOT NULL,"
    "  image_sha256     TEXT NOT NULL,"
    "  file_path        TEXT NOT NULL,"
    "  imported_by      TEXT NOT NULL,"
    "  imported_at      TEXT NOT NULL"
    ")",
    // 发布表：一次发布 = 把一个固件包推给一批设备。state 的取值就是设计 4.2 节状态机的各个状态。
    // release 是 SQL 关键字，表名加双引号
    "CREATE TABLE IF NOT EXISTS \"release\" ("
    "  release_id   INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  pkg_id       TEXT NOT NULL REFERENCES firmware(pkg_id),"
    "  state        TEXT NOT NULL CHECK (state IN ('draft','canary','observing','awaiting_full',"
    "                                              'full','paused','done','aborted')),"
    "  canary_group TEXT NOT NULL DEFAULT '',"
    "  concurrency  INTEGER NOT NULL DEFAULT 5,"
    "  created_by   TEXT NOT NULL,"
    "  created_at   TEXT NOT NULL"
    ")",
    kReleaseTargetTable,  // 发布目标表，语句在上面单独定义（升级旧数据库时还要用一次）
    // 审计日志表（设计第 13 章）：每行的 hash 由上一行的 hash 和本行其余字段算出，连成一条哈希链。
    // 只追加，程序里没有修改和删除这张表的语句
    "CREATE TABLE IF NOT EXISTS audit_log ("
    "  id        INTEGER PRIMARY KEY,"
    "  ts        TEXT NOT NULL,"
    "  level     TEXT NOT NULL,"
    "  category  TEXT NOT NULL,"
    "  actor     TEXT NOT NULL,"
    "  source    TEXT NOT NULL,"
    "  device_id TEXT NOT NULL,"
    "  message   TEXT NOT NULL,"
    "  prev_hash TEXT NOT NULL,"
    "  hash      TEXT NOT NULL"
    ")",
    // 设备事件表（设计 4.6 节）：(device_id, event_seq) 为主键，同一序号只入库一次。
    // 序号超过 device.event_ack 的行是“暂存”的，等设备补齐中间缺的序号
    "CREATE TABLE IF NOT EXISTS device_event ("
    "  device_id   TEXT NOT NULL REFERENCES device(device_id),"
    "  event_seq   INTEGER NOT NULL,"
    "  ts          TEXT NOT NULL,"
    "  kind        TEXT NOT NULL CHECK (kind IN ('progress','result','alert')),"
    "  payload     TEXT NOT NULL,"
    "  received_at TEXT NOT NULL,"
    "  PRIMARY KEY (device_id, event_seq)"
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
  // synchronous=FULL：每次提交都刷盘，断电不丢已提交的数据；
  // foreign_keys=ON：让表之间的 REFERENCES 约束生效（SQLite 默认不检查外键）
  QSqlQuery pragma(db);
  if (!pragma.exec(QStringLiteral("PRAGMA synchronous=FULL")) ||
      !pragma.exec(QStringLiteral("PRAGMA foreign_keys=ON"))) {
    *error = QStringLiteral("数据库初始化失败：%1").arg(pragma.lastError().text());
    return false;
  }
  // 先看结构版本：比本程序新的库是新版本程序建的，旧程序不认识新结构，硬用可能写坏数据
  const int found = schemaVersion();
  if (found > kSchemaVersion) {
    *error = QStringLiteral("数据库结构版本 %1 比本程序支持的 %2 新：回滚到旧版本时要先恢复升级前的数据库备份")
                 .arg(found)
                 .arg(kSchemaVersion);
    return false;
  }
  if (!createSchema(error) || !upgradeReleaseTarget(error)) return false;
  if (found != kSchemaVersion &&
      !pragma.exec(QStringLiteral("PRAGMA user_version = %1").arg(kSchemaVersion))) {
    *error = QStringLiteral("写入数据库结构版本失败：%1").arg(pragma.lastError().text());
    return false;
  }
  return true;
}

int Database::schemaVersion() const {
  QSqlQuery query(handle());
  if (!query.exec(QStringLiteral("PRAGMA user_version")) || !query.next()) return -1;
  return query.value(0).toInt();
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

bool Database::upgradeReleaseTarget(QString* error) {
  // 早期版本建的 release_target 表，status 的 CHECK 里还没有 held。
  // SQLite 不能修改 CHECK 约束，只能新建一张表把数据搬过去。建表语句里有 'held' 就说明不用升级
  QSqlDatabase db = handle();
  QSqlQuery query(db);
  query.prepare(QStringLiteral("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?"));
  query.addBindValue(QStringLiteral("release_target"));
  if (!query.exec() || !query.next()) {
    *error = QStringLiteral("读取表结构失败：%1").arg(query.lastError().text());
    return false;
  }
  if (query.value(0).toString().contains(QLatin1String("'held'"))) return true;
  query.finish();

  // 改名 → 按新结构建表 → 搬数据 → 删旧表，放在一个事务里，中途失败就全部撤销
  if (!db.transaction()) {
    *error = QStringLiteral("数据库升级失败：%1").arg(db.lastError().text());
    return false;
  }
  const QStringList steps = {
      QStringLiteral("ALTER TABLE release_target RENAME TO release_target_old"),
      QString::fromLatin1(kReleaseTargetTable),
      QStringLiteral("INSERT INTO release_target SELECT * FROM release_target_old"),
      QStringLiteral("DROP TABLE release_target_old"),
  };
  for (const QString& sql : steps) {
    if (!query.exec(sql)) {
      *error = QStringLiteral("数据库升级失败：%1").arg(query.lastError().text());
      db.rollback();
      return false;
    }
  }
  if (!db.commit()) {
    *error = QStringLiteral("数据库升级失败：%1").arg(db.lastError().text());
    return false;
  }
  return true;
}

}  // namespace fwds
