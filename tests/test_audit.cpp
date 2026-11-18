// 审计日志哈希链（设计第 13 章，用例 ST-33）与相关的存储、配置。
//   哈希链：正常追加后校验通过；改一行、删中间一行、删末尾、整体重算，都能被发现并定位；
//           重启后接着原来的链往后写
//   权限：  只有审计员能查看和校验；管理操作和发布操作写进审计表
//   数据库：早期版本的发布目标表（status 没有 held）打开时自动升级，数据保留
#include <QFile>
#include <QSqlError>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/config.h"
#include "server/security/audit_service.h"
#include "server/storage/database.h"
#include "tests/test_server_env.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class Audit : public ::testing::Test {
 protected:
  Audit() {
    QString error;
    EXPECT_TRUE(db.open(dir.filePath(QStringLiteral("a.db")), &error)) << error.toStdString();
    EXPECT_TRUE(log->load(&error)) << error.toStdString();
  }

  void appendSome(int n) {
    for (int i = 0; i < n; ++i) {
      ASSERT_TRUE(log->append(audit::kAdmin, QStringLiteral("INFO"), QStringLiteral("maint"),
                              QStringLiteral("host-1"), QString(),
                              QStringLiteral("action=test%1 result=ok").arg(i)));
    }
  }
  // 绕过程序、直接用 SQL 改数据库，模拟攻击者手工篡改。
  void sql(const QString& statement) {
    QSqlQuery query(db.handle());
    ASSERT_TRUE(query.exec(statement)) << statement.toStdString();
  }

  QTemporaryDir dir;
  Database db;
  QString checkpoint = dir.filePath(QStringLiteral("audit.checkpoint"));
  std::unique_ptr<AuditService> log = std::make_unique<AuditService>(&db, checkpoint);
};

}  // namespace

// 正常追加：每行的 prev_hash 是上一行的 hash，首行是 64 个 0；校验通过
TEST_F(Audit, ChainVerifies) {
  appendSome(5);
  const QList<AuditEntry> entries = log->recent(10);
  ASSERT_EQ(entries.size(), 5);
  EXPECT_EQ(entries.last().id, 1);
  EXPECT_EQ(entries.last().prevHash, kAuditGenesisHash);
  EXPECT_EQ(entries.first().prevHash, entries.at(1).hash);
  EXPECT_EQ(entries.first().hash, log->lastHash());
  const AuditCheck check = log->verify();
  EXPECT_TRUE(check.ok) << check.detail.toStdString();
  EXPECT_EQ(check.checkedRows, 5);
}

// ST-33 ①：改了第 3 行的内容 → 定位到第 3 行
TEST_F(Audit, ModifiedRowIsLocated) {
  appendSome(5);
  sql(QStringLiteral("UPDATE audit_log SET message = 'action=nothing' WHERE id = 3"));
  const AuditCheck check = log->verify();
  EXPECT_FALSE(check.ok);
  EXPECT_EQ(check.firstBadId, 3);
}

// ST-33 ②：删掉中间的第 2 行 → 第 3 行处报错（序号断了）
TEST_F(Audit, DeletedRowIsLocated) {
  appendSome(5);
  sql(QStringLiteral("DELETE FROM audit_log WHERE id = 2"));
  const AuditCheck check = log->verify();
  EXPECT_FALSE(check.ok);
  EXPECT_EQ(check.firstBadId, 3);
}

// 改了一行又把它的 hash 也重算了 → 下一行的 prev_hash 对不上
TEST_F(Audit, RehashedRowBreaksNextLink) {
  appendSome(5);
  sql(QStringLiteral("UPDATE audit_log SET message = 'x', hash = '%1' WHERE id = 2")
          .arg(QString(64, QLatin1Char('a'))));
  const AuditCheck check = log->verify();
  EXPECT_FALSE(check.ok);
  EXPECT_EQ(check.firstBadId, 2);  // 第 2 行自己的 hash 就和内容对不上
}

// 删掉末尾几行：链本身看不出来，靠检查点发现
TEST_F(Audit, TruncatedTailIsCaughtByCheckpoint) {
  appendSome(5);
  QString error;
  ASSERT_TRUE(log->writeCheckpoint(&error)) << error.toStdString();
  sql(QStringLiteral("DELETE FROM audit_log WHERE id >= 4"));
  const AuditCheck check = log->verify();
  EXPECT_FALSE(check.ok);
  EXPECT_TRUE(check.detail.contains(QStringLiteral("检查点"))) << check.detail.toStdString();
}

// 每 100 条自动写一次检查点；程序退出（析构）时也写
TEST_F(Audit, CheckpointWrittenEvery100AndOnExit) {
  appendSome(100);
  QFile file(checkpoint);
  ASSERT_TRUE(file.open(QIODevice::ReadOnly));
  EXPECT_EQ(file.readAll().trimmed(), QStringLiteral("100 %1").arg(log->lastHash()).toLatin1());
  file.close();
  appendSome(3);
  log.reset();  // 模拟程序退出
  ASSERT_TRUE(file.open(QIODevice::ReadOnly));
  EXPECT_TRUE(file.readAll().startsWith("103 "));
}

// 重启后接着原来的链写，校验仍然通过
TEST_F(Audit, ReloadContinuesChain) {
  appendSome(3);
  const QString last = log->lastHash();
  log = std::make_unique<AuditService>(&db, checkpoint);
  QString error;
  ASSERT_TRUE(log->load(&error)) << error.toStdString();
  EXPECT_EQ(log->lastId(), 3);
  EXPECT_EQ(log->lastHash(), last);
  appendSome(2);
  EXPECT_EQ(log->recent(1).first().prevHash, log->recent(2).at(1).hash);
  EXPECT_TRUE(log->verify().ok);
}

// 管理操作写进审计表（分类、操作者、来源主机）；只有审计员能查看和校验，校验本身也留痕
TEST(AuditAccess, AdminOperationsAreRecordedAndOnlyAuditorReads) {
  ServerBackend backend;
  QString error;
  backend.loginAsMaintainer();
  ASSERT_TRUE(backend.admin.setDispatchEnabled(true, &error));
  const AuditEntry entry = backend.audit.recent(1).first();
  EXPECT_EQ(entry.category, audit::kAdmin);
  EXPECT_EQ(entry.actor, QStringLiteral("maint"));
  EXPECT_EQ(entry.source, AuditService::localSource());
  EXPECT_TRUE(entry.message.startsWith(QStringLiteral("action=dispatch_on")));
  EXPECT_EQ(backend.audit.recent(10, audit::kAuth).first().message.left(12), QStringLiteral("action=login"));

  QList<AuditEntry> entries;
  AuditCheck check;
  EXPECT_FALSE(backend.admin.recentAudit(10, QString(), &entries, &error));
  EXPECT_FALSE(backend.admin.verifyAudit(&check, &error));
  ASSERT_TRUE(backend.auth.createAccount(QStringLiteral("auditor"), Role::Auditor,
                                         pwd("Audit-pass-01"), false, &error));
  ASSERT_EQ(backend.admin.login(QStringLiteral("auditor"), pwd("Audit-pass-01"), &error), AuthResult::Ok);
  ASSERT_TRUE(backend.admin.recentAudit(10, QString(), &entries, &error)) << error.toStdString();
  EXPECT_FALSE(entries.isEmpty());
  ASSERT_TRUE(backend.admin.verifyAudit(&check, &error)) << error.toStdString();
  EXPECT_TRUE(check.ok) << check.detail.toStdString();
  EXPECT_TRUE(backend.audit.recent(1).first().message.startsWith(QStringLiteral("action=audit_verify")));
}

// 早期版本建的发布目标表没有 held 状态：打开时升级表结构，原有数据不丢
TEST(DatabaseUpgrade, ReleaseTargetGainsHeldStatus) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("old.db"));
  {
    // 先建一个完整的库，再把发布目标表换成旧结构，放进一行引用了真实设备和发布的数据
    Database db;
    QString error;
    ASSERT_TRUE(db.open(path, &error)) << error.toStdString();
    QSqlQuery q(db.handle());
    const QStringList steps = {
        QStringLiteral("INSERT INTO device (device_id, model, status, cert_fingerprint, cert_not_after)"
                       " VALUES ('DEV-001', 'PLC-X200', 'active', 'ab', 'now')"),
        QStringLiteral("INSERT INTO firmware VALUES ('p1', 'PLC-X200', '2.1.0', 5, 1, 'cd', 'p1.fwpkg',"
                       " 'maint', 'now')"),
        QStringLiteral("INSERT INTO \"release\" (release_id, pkg_id, state, created_by, created_at)"
                       " VALUES (7, 'p1', 'canary', 'oper', 'now')"),
        QStringLiteral("DROP TABLE release_target"),
        QStringLiteral(
            "CREATE TABLE release_target (release_id INTEGER NOT NULL REFERENCES \"release\"(release_id),"
            " device_id TEXT NOT NULL REFERENCES device(device_id),"
            " phase TEXT NOT NULL CHECK (phase IN ('canary','full')),"
            " status TEXT NOT NULL CHECK (status IN ('pending','notified','success','failed',"
            " 'rolled_back','cancelled')), progress INTEGER NOT NULL DEFAULT 0,"
            " last_error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,"
            " PRIMARY KEY (release_id, device_id))"),
        QStringLiteral("INSERT INTO release_target VALUES (7, 'DEV-001', 'canary', 'notified', 40, '', 'now')"),
    };
    for (const QString& sql : steps) ASSERT_TRUE(q.exec(sql)) << q.lastError().text().toStdString();
    // 旧结构不接受 held
    EXPECT_FALSE(q.exec(QStringLiteral("UPDATE release_target SET status = 'held'")));
  }

  Database db;
  QString error;
  ASSERT_TRUE(db.open(path, &error)) << error.toStdString();
  QSqlQuery q(db.handle());
  ASSERT_TRUE(q.exec(QStringLiteral("SELECT status, progress FROM release_target WHERE release_id = 7")));
  ASSERT_TRUE(q.next());
  EXPECT_EQ(q.value(0).toString(), QStringLiteral("notified"));
  EXPECT_EQ(q.value(1).toInt(), 40);
  q.finish();
  EXPECT_TRUE(q.exec(QStringLiteral("UPDATE release_target SET status = 'held' WHERE release_id = 7")))
      << q.lastError().text().toStdString();
}

// [rollout] 段：不写用默认值（30 秒、5 台、20%）；写了按配置；越界报错。审计检查点默认跟着数据库文件
TEST(RolloutConfig, DefaultsAndOverrides) {
  QTemporaryDir dir;
  auto write = [&](const QByteArray& extra) {
    const QString path = dir.filePath(QStringLiteral("s.ini"));
    QFile f(path);
    EXPECT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write("[server]\nlisten_address=127.0.0.1\nlisten_port=9443\ndb_file=s.db\nfirmware_dir=fw\n"
            "fsk_pub_file=f.pem\nfsk_pub_sha256=" + QByteArray(64, 'a') +
            "\ncert_file=s.pem\nkey_file=s.key\n[tls]\nca_file=ca.pem\ncrl_file=crl.pem\n" + extra);
    return path;
  };
  ServerConfig cfg;
  QString error;
  ASSERT_TRUE(loadServerConfig(write(""), &cfg, &error)) << error.toStdString();
  EXPECT_EQ(cfg.rollout.observeMs, 30000);
  EXPECT_EQ(cfg.rollout.concurrency, 5);
  EXPECT_EQ(cfg.rollout.maxFailurePct, 20);
  EXPECT_EQ(cfg.auditCheckpointFile, QStringLiteral("s.db.audit-checkpoint"));

  ASSERT_TRUE(loadServerConfig(write("[rollout]\nobserve_s=60\nconcurrency=3\nmax_failure_pct=0\n"),
                               &cfg, &error)) << error.toStdString();
  EXPECT_EQ(cfg.rollout.observeMs, 60000);
  EXPECT_EQ(cfg.rollout.concurrency, 3);
  EXPECT_EQ(cfg.rollout.maxFailurePct, 0);

  EXPECT_FALSE(loadServerConfig(write("[rollout]\nconcurrency=0\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write("[rollout]\nmax_failure_pct=101\n"), &cfg, &error));
}
