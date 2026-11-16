#include "server/security/operator_auth.h"

#include <openssl/crypto.h>

#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

#include "common/crypto/rand.h"
#include "common/log.h"

namespace fwds {

namespace {

const char kKdfName[] = "pbkdf2-hmac-sha256";

QString toIso(const QDateTime& t) { return t.toUTC().toString(Qt::ISODate); }

QDateTime fromIso(const QVariant& v) {
  if (v.isNull()) return QDateTime();
  QDateTime t = QDateTime::fromString(v.toString(), Qt::ISODate);
  t.setTimeSpec(Qt::UTC);
  return t;
}

// 从一行查询结果取出给界面看的字段。列顺序：username, role, failed_count, locked_until, must_change
OperatorAccount accountFromRow(const QSqlQuery& q) {
  OperatorAccount a;
  a.username = q.value(0).toString();
  roleFromKey(q.value(1).toString(), &a.role);
  a.failedCount = q.value(2).toInt();
  a.lockedUntil = fromIso(q.value(3));
  a.mustChange = q.value(4).toInt() != 0;
  return a;
}

}  // namespace

bool roleAllows(Role role, Permission permission) {
  switch (permission) {
    case Permission::ViewStatus:
      return true;  // 三个角色都能看设备与发布状态
    case Permission::ManageRelease:
      return role == Role::Operator;
    case Permission::EmergencyStop:
      return role == Role::Operator || role == Role::Maintainer;
    case Permission::ManageDevices:
    case Permission::ImportFirmware:
    case Permission::ImportCrl:
    case Permission::ToggleDispatch:
    case Permission::ManageAccounts:
      return role == Role::Maintainer;
    case Permission::ViewAudit:
      return role == Role::Auditor;
  }
  return false;  // 没列出的功能一律不允许
}

QString roleKey(Role role) {
  switch (role) {
    case Role::Operator: return QStringLiteral("operator");
    case Role::Maintainer: return QStringLiteral("maintainer");
    case Role::Auditor: return QStringLiteral("auditor");
  }
  return QString();
}

bool roleFromKey(const QString& key, Role* role) {
  if (key == QLatin1String("operator")) *role = Role::Operator;
  else if (key == QLatin1String("maintainer")) *role = Role::Maintainer;
  else if (key == QLatin1String("auditor")) *role = Role::Auditor;
  else return false;
  return true;
}

QString roleDisplayName(Role role) {
  switch (role) {
    case Role::Operator: return QStringLiteral("操作员");
    case Role::Maintainer: return QStringLiteral("维护员");
    case Role::Auditor: return QStringLiteral("审计员");
  }
  return QString();
}

SecureBuffer passwordFromString(const QString& text) {
  QByteArray utf8 = text.toUtf8();
  SecureBuffer out = SecureBuffer::fromBytes(utf8.constData(), static_cast<int>(utf8.size()));
  OPENSSL_cleanse(utf8.data(), static_cast<size_t>(utf8.size()));
  return out;
}

bool samePassword(const SecureBuffer& a, const SecureBuffer& b) {
  return a.size() == b.size() &&
         CRYPTO_memcmp(a.data(), b.data(), static_cast<size_t>(a.size())) == 0;
}

bool isValidUsername(const QString& username) {
  if (username.size() < 3 || username.size() > 32) return false;
  for (const QChar c : username) {
    const bool ok = (c >= QLatin1Char('a') && c <= QLatin1Char('z')) ||
                    (c >= QLatin1Char('A') && c <= QLatin1Char('Z')) ||
                    (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('_') ||
                    c == QLatin1Char('.') || c == QLatin1Char('-');
    if (!ok) return false;
  }
  return true;
}

QString checkPasswordPolicy(const SecureBuffer& password) {
  if (password.size() < kPwdMinLength || password.size() > kPwdMaxLength) {
    return QStringLiteral("口令长度须为 %1 ~ %2 个字节").arg(kPwdMinLength).arg(kPwdMaxLength);
  }
  bool hasLetter = false;
  bool hasDigit = false;
  for (int i = 0; i < password.size(); ++i) {
    const unsigned char c = password.data()[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) hasLetter = true;
    if (c >= '0' && c <= '9') hasDigit = true;
  }
  if (!hasLetter || !hasDigit) return QStringLiteral("口令须同时包含字母和数字");
  return QString();
}

OperatorAuth::OperatorAuth(Database* db, int iterations) : db_(db), iterations_(iterations) {}

bool OperatorAuth::derive(const SecureBuffer& password, const QByteArray& salt, int iterations,
                          SecureBuffer* hash) const {
  return pbkdf2Sha256(password, salt, iterations, kPwdHashSize, hash);
}

bool OperatorAuth::isEmpty() const {
  QSqlQuery q(db_->handle());
  return q.exec(QStringLiteral("SELECT COUNT(*) FROM operator")) && q.next() &&
         q.value(0).toInt() == 0;
}

bool OperatorAuth::createAccount(const QString& username, Role role, const SecureBuffer& password,
                                 bool mustChange, QString* error) {
  if (!isValidUsername(username)) {
    *error = QStringLiteral("账号名须为 3 ~ 32 个字母、数字、下划线、点或减号");
    return false;
  }
  *error = checkPasswordPolicy(password);
  if (!error->isEmpty()) return false;
  if (find(username, nullptr)) {
    *error = QStringLiteral("账号 %1 已存在").arg(username);
    return false;
  }

  // 每个账号一份新的随机盐：两个账号口令相同，存下来的派生结果也不同
  const QByteArray salt = randomBytes(kKdfSaltSize);
  SecureBuffer hash;
  if (!derive(password, salt, iterations_, &hash)) {
    *error = QStringLiteral("口令派生失败");
    return false;
  }

  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "INSERT INTO operator (username, role, kdf, kdf_iter, salt, pwd_hash, must_change) "
      "VALUES (?, ?, ?, ?, ?, ?, ?)"));
  q.addBindValue(username);
  q.addBindValue(roleKey(role));
  q.addBindValue(QString::fromLatin1(kKdfName));
  q.addBindValue(iterations_);
  q.addBindValue(salt);
  q.addBindValue(QByteArray(reinterpret_cast<const char*>(hash.data()), hash.size()));
  q.addBindValue(mustChange ? 1 : 0);
  if (!q.exec()) {
    *error = QStringLiteral("写账号表失败：%1").arg(q.lastError().text());
    return false;
  }
  return true;
}

AuthResult OperatorAuth::verify(const QString& username, const SecureBuffer& password,
                                OperatorAccount* account, const QDateTime& now) {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "SELECT username, role, failed_count, locked_until, must_change, kdf, kdf_iter, salt, pwd_hash "
      "FROM operator WHERE username = ?"));
  q.addBindValue(username);
  if (!q.exec() || !q.next()) {
    // 账号不存在也照样派生一次，让“账号不存在”和“口令不对”耗时相近，
    // 不给攻击者用响应时间探测账号名的机会
    SecureBuffer unused;
    derive(password, QByteArray(kKdfSaltSize, '\0'), iterations_, &unused);
    return AuthResult::BadCredentials;
  }

  OperatorAccount row = accountFromRow(q);
  const QString kdf = q.value(5).toString();
  const int iterations = q.value(6).toInt();
  const QByteArray salt = q.value(7).toByteArray();
  const QByteArray stored = q.value(8).toByteArray();

  // 锁定期内直接拒绝：不派生、不计数，输对了也不行
  if (row.lockedUntil.isValid() && now < row.lockedUntil) {
    if (account) *account = row;
    return AuthResult::Locked;
  }
  // 锁定已到期：从 0 重新计数
  if (row.lockedUntil.isValid()) row.failedCount = 0;

  // 账号表被人改过（换了派生函数名、调低迭代次数、截短哈希）时一律按口令错误处理
  SecureBuffer hash;
  bool match = false;
  if (kdf == QLatin1String(kKdfName) && iterations >= kPwdMinIterations &&
      stored.size() == kPwdHashSize && derive(password, salt, iterations, &hash)) {
    // 常数时间比较：耗时与“前多少个字节相同”无关
    match = CRYPTO_memcmp(hash.data(), stored.constData(), kPwdHashSize) == 0;
  }

  QSqlQuery update(db_->handle());
  update.prepare(QStringLiteral(
      "UPDATE operator SET failed_count = ?, locked_until = ? WHERE username = ?"));
  if (match) {
    row.failedCount = 0;
    row.lockedUntil = QDateTime();
  } else {
    ++row.failedCount;
    if (row.failedCount >= kPwdMaxFailures) {
      row.lockedUntil = now.addSecs(kPwdLockMinutes * 60);
      qCCritical(lcSecurity).noquote()
          << "operator account" << username << "locked until" << toIso(row.lockedUntil) << "after"
          << row.failedCount << "failed logins";
    } else {
      row.lockedUntil = QDateTime();
    }
  }
  update.addBindValue(row.failedCount);
  update.addBindValue(row.lockedUntil.isValid() ? QVariant(toIso(row.lockedUntil)) : QVariant());
  update.addBindValue(username);
  if (!update.exec()) {
    // 计数写不进去就不能放行，否则锁定形同虚设
    qCCritical(lcSecurity) << "cannot update login counter:" << update.lastError().text();
    return AuthResult::BadCredentials;
  }

  if (account) *account = row;
  return match ? AuthResult::Ok : AuthResult::BadCredentials;
}

bool OperatorAuth::setPassword(const QString& username, const SecureBuffer& password,
                               bool mustChange, QString* error) {
  *error = checkPasswordPolicy(password);
  if (!error->isEmpty()) return false;
  const QByteArray salt = randomBytes(kKdfSaltSize);  // 换口令同时换盐
  SecureBuffer hash;
  if (!derive(password, salt, iterations_, &hash)) {
    *error = QStringLiteral("口令派生失败");
    return false;
  }
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "UPDATE operator SET kdf = ?, kdf_iter = ?, salt = ?, pwd_hash = ?, must_change = ?, "
      "failed_count = 0, locked_until = NULL WHERE username = ?"));
  q.addBindValue(QString::fromLatin1(kKdfName));
  q.addBindValue(iterations_);
  q.addBindValue(salt);
  q.addBindValue(QByteArray(reinterpret_cast<const char*>(hash.data()), hash.size()));
  q.addBindValue(mustChange ? 1 : 0);
  q.addBindValue(username);
  if (!q.exec() || q.numRowsAffected() != 1) {
    *error = QStringLiteral("账号 %1 不存在").arg(username);
    return false;
  }
  return true;
}

bool OperatorAuth::removeAccount(const QString& username, QString* error) {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("DELETE FROM operator WHERE username = ?"));
  q.addBindValue(username);
  if (!q.exec() || q.numRowsAffected() != 1) {
    *error = QStringLiteral("账号 %1 不存在").arg(username);
    return false;
  }
  return true;
}

bool OperatorAuth::unlock(const QString& username, QString* error) {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "UPDATE operator SET failed_count = 0, locked_until = NULL WHERE username = ?"));
  q.addBindValue(username);
  if (!q.exec() || q.numRowsAffected() != 1) {
    *error = QStringLiteral("账号 %1 不存在").arg(username);
    return false;
  }
  return true;
}

bool OperatorAuth::find(const QString& username, OperatorAccount* account) const {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral(
      "SELECT username, role, failed_count, locked_until, must_change FROM operator "
      "WHERE username = ?"));
  q.addBindValue(username);
  if (!q.exec() || !q.next()) return false;
  if (account) *account = accountFromRow(q);
  return true;
}

QList<OperatorAccount> OperatorAuth::accounts() const {
  QList<OperatorAccount> list;
  QSqlQuery q(db_->handle());
  if (!q.exec(QStringLiteral("SELECT username, role, failed_count, locked_until, must_change "
                             "FROM operator ORDER BY username"))) {
    return list;
  }
  while (q.next()) list.append(accountFromRow(q));
  return list;
}

int OperatorAuth::countByRole(Role role) const {
  QSqlQuery q(db_->handle());
  q.prepare(QStringLiteral("SELECT COUNT(*) FROM operator WHERE role = ?"));
  q.addBindValue(roleKey(role));
  return q.exec() && q.next() ? q.value(0).toInt() : 0;
}

}  // namespace fwds
