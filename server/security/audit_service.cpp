#include "server/security/audit_service.h"

#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QSysInfo>

#include "common/crypto/sha256.h"
#include "common/log.h"

namespace fwds {

namespace {

constexpr qint64 kCheckpointEvery = 100;  // 每多少条写一次检查点

const char kSelectColumns[] =
    "SELECT id, ts, level, category, actor, source, device_id, message, prev_hash, hash "
    "FROM audit_log ";

AuditEntry entryFromQuery(const QSqlQuery& query) {
  AuditEntry e;
  e.id = query.value(0).toLongLong();
  e.ts = QDateTime::fromString(query.value(1).toString(), Qt::ISODateWithMs);
  e.level = query.value(2).toString();
  e.category = query.value(3).toString();
  e.actor = query.value(4).toString();
  e.source = query.value(5).toString();
  e.deviceId = query.value(6).toString();
  e.message = query.value(7).toString();
  e.prevHash = query.value(8).toString();
  e.hash = query.value(9).toString();
  return e;
}

// 读检查点文件：一行“序号 hash”。文件不存在时返回 false。
bool readCheckpoint(const QString& path, qint64* id, QString* hash) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) return false;
  const QList<QByteArray> parts = file.readAll().trimmed().split(' ');
  if (parts.size() != 2) return false;
  bool ok = false;
  *id = parts.at(0).toLongLong(&ok);
  *hash = QString::fromLatin1(parts.at(1));
  return ok;
}

}  // namespace

AuditService::AuditService(Database* db, const QString& checkpointFile, QObject* parent)
    : QObject(parent), db_(db), checkpointFile_(checkpointFile), lastHash_(kAuditGenesisHash) {}

AuditService::~AuditService() {
  // 程序退出时把最新的 hash 记下来（设计第 13 章）
  QString error;
  if (lastId_ > 0 && !writeCheckpoint(&error)) {
    qCWarning(lcAudit).noquote() << "audit checkpoint not written:" << error;
  }
}

QString AuditService::localSource() { return QSysInfo::machineHostName(); }

QString AuditService::computeHash(const AuditEntry& e) {
  // hash = SHA-256(prev_hash ‖ 其余字段)。其余字段排成一个 JSON 数组再取 UTF-8 字节：
  // 每个字段都有引号和分隔符，字段内容里出现什么字符都不会和相邻字段混在一起
  const QJsonArray fields = {QString::number(e.id), e.ts.toString(Qt::ISODateWithMs), e.level,
                             e.category, e.actor, e.source, e.deviceId, e.message};
  QByteArray input = e.prevHash.toLatin1();
  input += QJsonDocument(fields).toJson(QJsonDocument::Compact);
  return QString::fromLatin1(sha256(input).toHex());
}

bool AuditService::load(QString* error) {
  QSqlQuery query(db_->handle());
  if (!query.exec(QStringLiteral("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1"))) {
    *error = QStringLiteral("读取审计日志失败：%1").arg(query.lastError().text());
    return false;
  }
  if (query.next()) {
    lastId_ = query.value(0).toLongLong();
    lastHash_ = query.value(1).toString();
  }
  return true;
}

bool AuditService::append(const QString& category, const QString& level, const QString& actor,
                          const QString& source, const QString& deviceId, const QString& message) {
  // 空的 QString 会被绑成 SQL NULL，而这几列都是 NOT NULL：统一换成空串
  auto text = [](const QString& s) { return s.isNull() ? QStringLiteral("") : s; };
  AuditEntry e;
  e.id = lastId_ + 1;  // 序号连续，自己分配，参与 hash 计算
  e.ts = QDateTime::currentDateTimeUtc();
  e.level = text(level);
  e.category = text(category);
  e.actor = actor.isEmpty() ? QStringLiteral("-") : actor;
  e.source = text(source);
  e.deviceId = text(deviceId);
  e.message = text(message);
  e.prevHash = lastHash_;
  e.hash = computeHash(e);

  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "INSERT INTO audit_log (id, ts, level, category, actor, source, device_id, message, "
      "prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"));
  query.addBindValue(e.id);
  query.addBindValue(e.ts.toString(Qt::ISODateWithMs));
  query.addBindValue(e.level);
  query.addBindValue(e.category);
  query.addBindValue(e.actor);
  query.addBindValue(e.source);
  query.addBindValue(e.deviceId);
  query.addBindValue(e.message);
  query.addBindValue(e.prevHash);
  query.addBindValue(e.hash);
  if (!query.exec()) {
    qCWarning(lcAudit) << "audit_log insert failed:" << query.lastError().text();
    return false;
  }
  lastId_ = e.id;
  lastHash_ = e.hash;
  if (lastId_ % kCheckpointEvery == 0) {
    QString error;
    if (!writeCheckpoint(&error)) qCWarning(lcAudit).noquote() << error;
  }
  emit appended();
  return true;
}

QList<AuditEntry> AuditService::recent(int limit, const QString& category) const {
  QList<AuditEntry> list;
  QSqlQuery query(db_->handle());
  if (category.isEmpty()) {
    query.prepare(QString::fromLatin1(kSelectColumns) + QStringLiteral("ORDER BY id DESC LIMIT ?"));
  } else {
    query.prepare(QString::fromLatin1(kSelectColumns) +
                  QStringLiteral("WHERE category = ? ORDER BY id DESC LIMIT ?"));
    query.addBindValue(category);
  }
  query.addBindValue(limit);
  if (!query.exec()) {
    qCWarning(lcAudit) << "audit_log query failed:" << query.lastError().text();
    return list;
  }
  while (query.next()) list.append(entryFromQuery(query));
  return list;
}

AuditCheck AuditService::verify() const {
  AuditCheck result;
  QSqlQuery query(db_->handle());
  query.setForwardOnly(true);  // 一行一行往下读，不把整张表留在内存里
  if (!query.exec(QString::fromLatin1(kSelectColumns) + QStringLiteral("ORDER BY id"))) {
    result.detail = QStringLiteral("读取审计日志失败：%1").arg(query.lastError().text());
    return result;
  }
  QString expectedPrev = kAuditGenesisHash;
  qint64 expectedId = 1;
  QHash<qint64, QString> hashes;  // 只为核对检查点，记一下每行的 hash
  while (query.next()) {
    const AuditEntry e = entryFromQuery(query);
    // ① 序号必须从 1 开始连续：中间缺号说明有记录被删除
    if (e.id != expectedId) {
      result.firstBadId = e.id;
      result.detail = QStringLiteral("第 %1 条之前缺少记录（期望序号 %2），有记录被删除")
                          .arg(e.id)
                          .arg(expectedId);
      return result;
    }
    // ② prev_hash 必须等于上一行的 hash：对不上说明上一行被改过或被删除过
    if (e.prevHash != expectedPrev) {
      result.firstBadId = e.id;
      result.detail = QStringLiteral("第 %1 条的前一条哈希对不上，前面的记录被改动或删除").arg(e.id);
      return result;
    }
    // ③ 用本行内容重算 hash：对不上说明本行被改过
    if (computeHash(e) != e.hash) {
      result.firstBadId = e.id;
      result.detail = QStringLiteral("第 %1 条的内容与它的哈希不符，这条记录被改动过").arg(e.id);
      return result;
    }
    hashes.insert(e.id, e.hash);
    expectedPrev = e.hash;
    ++expectedId;
    ++result.checkedRows;
  }

  // ④ 检查点：记下的那一行必须还在、hash 必须一样。末尾被删、整条链被重算，都在这里露馅
  qint64 checkpointId = 0;
  QString checkpointHash;
  if (!readCheckpoint(checkpointFile_, &checkpointId, &checkpointHash)) {
    result.ok = true;
    result.detail = QStringLiteral("哈希链完整，共 %1 条。没有检查点文件，无法确认末尾的记录没有被删除")
                        .arg(result.checkedRows);
    return result;
  }
  if (!hashes.contains(checkpointId)) {
    result.detail = QStringLiteral("检查点记录的第 %1 条已经不存在，末尾的记录被删除").arg(checkpointId);
    return result;
  }
  if (hashes.value(checkpointId) != checkpointHash) {
    result.firstBadId = checkpointId;
    result.detail = QStringLiteral("第 %1 条的哈希与检查点不一致，日志被整体改写过").arg(checkpointId);
    return result;
  }
  result.ok = true;
  result.detail = QStringLiteral("哈希链完整，共 %1 条；与检查点（第 %2 条）一致")
                      .arg(result.checkedRows)
                      .arg(checkpointId);
  return result;
}

bool AuditService::writeCheckpoint(QString* error) {
  // 先写临时文件再改名，写到一半断电也不会留下半个检查点
  QSaveFile file(checkpointFile_);
  if (!file.open(QIODevice::WriteOnly)) {
    *error = QStringLiteral("无法写审计检查点文件 %1").arg(checkpointFile_);
    return false;
  }
  file.write(QStringLiteral("%1 %2\n").arg(lastId_).arg(lastHash_).toLatin1());
  if (!file.commit()) {
    *error = QStringLiteral("无法写审计检查点文件 %1").arg(checkpointFile_);
    return false;
  }
  return true;
}

}  // namespace fwds
