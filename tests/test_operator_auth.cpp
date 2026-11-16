// 账号口令与角色权限（设计第 11 章）。对应测试报告 UT-06、ST-13、ST-14 的自动化部分。
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "tests/test_server_env.h"

using namespace fwds;
using fwds_test::kTestIterations;
using fwds_test::pwd;

namespace {

struct AuthFixture {
  AuthFixture() {
    QString error;
    EXPECT_TRUE(db.open(QStringLiteral(":memory:"), &error)) << error.toStdString();
  }
  // 直接读账号表的一行（模拟拿到数据库文件的人能看到什么）
  QSqlQuery row(const QString& username) {
    QSqlQuery q(db.handle());
    q.prepare(QStringLiteral(
        "SELECT kdf, kdf_iter, salt, pwd_hash, failed_count, locked_until FROM operator "
        "WHERE username = ?"));
    q.addBindValue(username);
    EXPECT_TRUE(q.exec() && q.next());
    return q;
  }
  Database db;
  OperatorAuth auth{&db, kTestIterations};
};

}  // namespace

// 设计 11.2 节：默认迭代 600 000 次
TEST(OperatorAuth, DefaultIterationsMatchDesign) {
  EXPECT_EQ(kKdfDefaultIterations, 600000);
  AuthFixture fx;
  OperatorAuth production(&fx.db);  // 不指定迭代次数 = 生产配置
  QString error;
  QElapsedTimer timer;
  timer.start();
  ASSERT_TRUE(production.createAccount(QStringLiteral("alice"), Role::Operator,
                                       pwd("Correct-horse-9"), false, &error));
  const qint64 elapsed = timer.elapsed();
  EXPECT_EQ(fx.row(QStringLiteral("alice")).value(1).toInt(), 600000);
  // UT-06：单次派生是“慢”的（毫秒级以上），不是一次哈希的微秒级
  EXPECT_GE(elapsed, 20);
  EXPECT_EQ(production.verify(QStringLiteral("alice"), pwd("Correct-horse-9"), nullptr),
            AuthResult::Ok);
}

// UT-06 / ST-13：相同口令的两个账号，盐和存储值都不同；库里没有明文，也不是单次 SHA-256
TEST(OperatorAuth, SamePasswordGivesDifferentStoredValues) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Same-pass-123"),
                                    false, &error));
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("bob"), Role::Auditor, pwd("Same-pass-123"),
                                    false, &error));
  QSqlQuery a = fx.row(QStringLiteral("alice"));
  QSqlQuery b = fx.row(QStringLiteral("bob"));
  EXPECT_EQ(a.value(0).toString(), QStringLiteral("pbkdf2-hmac-sha256"));
  EXPECT_EQ(a.value(2).toByteArray().size(), 16);
  EXPECT_EQ(a.value(3).toByteArray().size(), 32);
  EXPECT_NE(a.value(2).toByteArray(), b.value(2).toByteArray());  // 盐不同
  EXPECT_NE(a.value(3).toByteArray(), b.value(3).toByteArray());  // 存储值不同

  const QByteArray plain = "Same-pass-123";
  EXPECT_FALSE(a.value(3).toByteArray().contains(plain));
  EXPECT_NE(a.value(3).toByteArray(), QCryptographicHash::hash(plain, QCryptographicHash::Sha256));
  EXPECT_NE(a.value(3).toByteArray(),
            QCryptographicHash::hash(a.value(2).toByteArray() + plain, QCryptographicHash::Sha256));
}

TEST(OperatorAuth, VerifyAcceptsRightAndRejectsWrongPassword) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Maintainer, pwd("Right-pass-01"),
                                    false, &error));
  OperatorAccount account;
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), &account), AuthResult::Ok);
  EXPECT_EQ(account.role, Role::Maintainer);
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-02"), nullptr),
            AuthResult::BadCredentials);
  // 账号不存在和口令不对，对外是同一个结果
  EXPECT_EQ(fx.auth.verify(QStringLiteral("nobody"), pwd("Right-pass-01"), nullptr),
            AuthResult::BadCredentials);
}

TEST(OperatorAuth, RejectsWeakPasswordsAndBadUsernames) {
  AuthFixture fx;
  QString error;
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("short1"), false,
                                     &error));
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("onlyletters-x"),
                                     false, &error));
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("1234567890123"),
                                     false, &error));
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("a"), Role::Operator, pwd("Good-pass-123"), false,
                                     &error));
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("al ice'--"), Role::Operator,
                                     pwd("Good-pass-123"), false, &error));
  EXPECT_TRUE(fx.auth.isEmpty());
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Good-pass-123"),
                                    false, &error));
  EXPECT_FALSE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Good-pass-456"),
                                     false, &error));  // 重名
}

// ST-14：连续输错 5 次锁定 10 分钟；锁定期内输对也不行；到期后恢复
TEST(OperatorAuth, LocksAfterFiveFailuresForTenMinutes) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Right-pass-01"),
                                    false, &error));
  const QDateTime t0 = QDateTime::currentDateTimeUtc();
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Wrong-pass-00"), nullptr, t0),
              AuthResult::BadCredentials);
  }
  OperatorAccount account;
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Wrong-pass-00"), &account, t0),
            AuthResult::BadCredentials);  // 第 5 次：触发锁定
  EXPECT_EQ(account.failedCount, 5);
  EXPECT_EQ(account.lockedUntil, t0.addSecs(600));

  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr, t0.addSecs(1)),
            AuthResult::Locked);
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr, t0.addSecs(599)),
            AuthResult::Locked);
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), &account, t0.addSecs(600)),
            AuthResult::Ok);
  EXPECT_EQ(account.failedCount, 0);
}

TEST(OperatorAuth, SuccessResetsFailureCounter) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Right-pass-01"),
                                    false, &error));
  for (int round = 0; round < 2; ++round) {
    for (int i = 0; i < 4; ++i) fx.auth.verify(QStringLiteral("alice"), pwd("Wrong-pass-00"), nullptr);
    EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr), AuthResult::Ok);
  }
}

// 失败计数和锁定存在数据库文件里：重启程序（重新打开数据库）不会清零
TEST(OperatorAuth, LockSurvivesRestart) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("auth.db"));
  QString error;
  {
    Database db;
    ASSERT_TRUE(db.open(path, &error));
    OperatorAuth auth(&db, kTestIterations);
    ASSERT_TRUE(auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Right-pass-01"),
                                   false, &error));
    for (int i = 0; i < 5; ++i) auth.verify(QStringLiteral("alice"), pwd("Wrong-pass-00"), nullptr);
  }
  Database db;
  ASSERT_TRUE(db.open(path, &error));
  OperatorAuth auth(&db, kTestIterations);
  EXPECT_EQ(auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr), AuthResult::Locked);
  ASSERT_TRUE(auth.unlock(QStringLiteral("alice"), &error));
  EXPECT_EQ(auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr), AuthResult::Ok);
  // 数据库文件只有运行账户可读写
  EXPECT_EQ(QFile::permissions(path) & (QFileDevice::ReadGroup | QFileDevice::ReadOther |
                                        QFileDevice::WriteGroup | QFileDevice::WriteOther),
            QFileDevice::Permissions());
}

// 有人直接改数据库把迭代次数调低（想让离线猜口令变快）：这条记录不再能登录
TEST(OperatorAuth, TamperedKdfParametersAreRejected) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Right-pass-01"),
                                    false, &error));
  QSqlQuery q(fx.db.handle());
  ASSERT_TRUE(q.exec(QStringLiteral("UPDATE operator SET kdf_iter = 1 WHERE username = 'alice'")));
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr),
            AuthResult::BadCredentials);
}

TEST(OperatorAuth, SetPasswordChangesSaltAndClearsLock) {
  AuthFixture fx;
  QString error;
  ASSERT_TRUE(fx.auth.createAccount(QStringLiteral("alice"), Role::Operator, pwd("Right-pass-01"),
                                    false, &error));
  const QByteArray oldSalt = fx.row(QStringLiteral("alice")).value(2).toByteArray();
  for (int i = 0; i < 5; ++i) fx.auth.verify(QStringLiteral("alice"), pwd("Wrong-pass-00"), nullptr);
  ASSERT_TRUE(fx.auth.setPassword(QStringLiteral("alice"), pwd("Brand-new-77"), true, &error));
  EXPECT_NE(fx.row(QStringLiteral("alice")).value(2).toByteArray(), oldSalt);
  OperatorAccount account;
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Brand-new-77"), &account), AuthResult::Ok);
  EXPECT_TRUE(account.mustChange);
  EXPECT_EQ(fx.auth.verify(QStringLiteral("alice"), pwd("Right-pass-01"), nullptr),
            AuthResult::BadCredentials);
}

// 设计 11.1 节权限表，逐格核对
TEST(OperatorAuth, RolePermissionTableMatchesDesign) {
  struct Row {
    Permission permission;
    bool op, maint, audit;
  };
  const Row table[] = {
      {Permission::ViewStatus, true, true, true},
      {Permission::ManageRelease, true, false, false},
      {Permission::EmergencyStop, true, true, false},
      {Permission::ManageDevices, false, true, false},
      {Permission::ImportFirmware, false, true, false},
      {Permission::ImportCrl, false, true, false},
      {Permission::ToggleDispatch, false, true, false},
      {Permission::ManageAccounts, false, true, false},
      {Permission::ViewAudit, false, false, true},
  };
  for (const Row& row : table) {
    EXPECT_EQ(roleAllows(Role::Operator, row.permission), row.op);
    EXPECT_EQ(roleAllows(Role::Maintainer, row.permission), row.maint);
    EXPECT_EQ(roleAllows(Role::Auditor, row.permission), row.audit);
  }
}
