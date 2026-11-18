// 设备侧事件写进审计日志（设计第 13 章）：DeviceAudit 把设备的登录、断线、升级、告警和
// 被拒的连接按 CONN / UPGRADE / SECURITY 分类追加到哈希链里，来源记设备的 IP。
// 真实 TLS、真实 TcpServer / TcpClient，接线和 fwds-server 一样（tests/test_live.h）。
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "server/security/audit_service.h"
#include "tests/test_device.h"
#include "tests/test_live.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class DeviceAuditTest : public ::testing::Test {
 protected:
  DeviceAuditTest() { backend.registerDevice(sharedPki().dev001); }

  QString importFirmware(const QString& version, int securityVersion) {
    const DeviceFirmware fw(version, securityVersion, 3 * kChunkSize + 5);
    Manifest manifest;
    const QString path = packageFileFor(fw, dir.path(), QStringLiteral("fw-") + version, &manifest);
    backend.importFirmware(path);
    return manifest.pkgId;
  }
  bool deviceReady() {
    return waitFor([&]() {
      DeviceRecord record;
      return backend.registry.find(kDev1, &record) && record.online && !record.upgradeState.isEmpty();
    });
  }
  // 某一类里内容以 prefix 开头的记录。
  QList<AuditEntry> find(const QString& category, const QString& prefix) {
    QList<AuditEntry> found;
    for (const AuditEntry& e : backend.audit.recent(1000, category)) {
      if (e.message.startsWith(prefix)) found.append(e);
    }
    return found;
  }

  const QString kDev1 = QStringLiteral("DEV-001");
  QTemporaryDir dir;
  ServerBackend backend;
  QString error;
};

}  // namespace

// 一次正常升级：登录（CONN）→ 开始升级、升级结果（UPGRADE）→ 重启断开、重新登录（CONN）。
// 每条的操作者和设备都是 DEV-001，来源是它的 IP；哈希链照常校验通过
TEST_F(DeviceAuditTest, LoginUpgradeAndReconnectAreAudited) {
  LiveServer fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  LiveDevice dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();
  ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, pwd("Oper-pass-01"), &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return !find(audit::kUpgrade, QStringLiteral("升级结果")).isEmpty(); }, 15000));
  ASSERT_TRUE(waitFor([&]() { return find(audit::kConn, QStringLiteral("设备登录")).size() == 2; }));

  const QList<AuditEntry> logins = find(audit::kConn, QStringLiteral("设备登录"));
  EXPECT_TRUE(logins.last().message.contains(QStringLiteral("2.0.0")));   // 第一次登录（从新到旧排，最后一条最早）
  EXPECT_TRUE(logins.first().message.contains(QStringLiteral("2.1.0")));  // 重启后带着新版本登录
  EXPECT_EQ(find(audit::kConn, QStringLiteral("连接断开")).size(), 1);     // 模拟重启时的断开

  const QList<AuditEntry> started = find(audit::kUpgrade, QStringLiteral("收到升级通知"));
  ASSERT_EQ(started.size(), 1);
  EXPECT_TRUE(started.first().message.contains(pkgId));
  const AuditEntry result = find(audit::kUpgrade, QStringLiteral("升级结果")).first();
  EXPECT_TRUE(result.message.startsWith(QStringLiteral("升级结果 SUCCESS"))) << result.message.toStdString();
  EXPECT_EQ(result.level, QStringLiteral("INFO"));
  for (const AuditEntry& e : logins + started + QList<AuditEntry>{result}) {
    EXPECT_EQ(e.actor, kDev1);
    EXPECT_EQ(e.deviceId, kDev1);
    EXPECT_EQ(e.source, QStringLiteral("127.0.0.1"));
  }
  EXPECT_TRUE(backend.audit.verify().ok);
}

// 设备拒绝降级时上报的 ALERT 记 SECURITY（WARN），结果 FAILED 记 UPGRADE（WARN）
TEST_F(DeviceAuditTest, DeviceAlertIsSecurityEntry) {
  LiveServer fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("1.9.0"), 3);
  LiveDevice dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();
  ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, pwd("Oper-pass-01"), &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return !find(audit::kUpgrade, QStringLiteral("升级结果")).isEmpty(); }, 5000));

  const QList<AuditEntry> alerts = find(audit::kSecurity, QStringLiteral("设备安全告警 3003"));
  ASSERT_EQ(alerts.size(), 1);
  EXPECT_EQ(alerts.first().level, QStringLiteral("WARN"));
  EXPECT_EQ(alerts.first().deviceId, kDev1);
  const AuditEntry result = find(audit::kUpgrade, QStringLiteral("升级结果")).first();
  EXPECT_TRUE(result.message.startsWith(QStringLiteral("升级结果 FAILED"))) << result.message.toStdString();
  EXPECT_TRUE(result.message.contains(QStringLiteral("3003")));
  EXPECT_EQ(result.level, QStringLiteral("WARN"));
}

// 没注册的设备（证书有效，但注册表里没有）反复登录：每次被拒都记 SECURITY，
// 同一个 IP 一分钟最多记 kMaxRejectsPerMinute 条，审计日志不会被刷爆
TEST_F(DeviceAuditTest, RejectedLoginsAreAuditedWithRateLimit) {
  LiveServer fx(&backend);
  LiveDevice stranger(fx.port(), sharedPki().dev003, QStringLiteral("DEV-003"),
                      dir.filePath(QStringLiteral("dev3")));
  ASSERT_TRUE(waitFor([&]() { return !find(audit::kSecurity, QStringLiteral("连接被拒：登录失败")).isEmpty(); }));
  spin(1500);  // 设备按 30 ms 的退避不停重连，远远超过 20 次
  stranger.client->stop();

  const QList<AuditEntry> rejected = find(audit::kSecurity, QStringLiteral("连接被拒：登录失败"));
  EXPECT_GE(rejected.size(), 2);
  EXPECT_LE(rejected.size(), kMaxRejectsPerMinute);
  EXPECT_EQ(rejected.last().message, QStringLiteral("连接被拒：登录失败 2005"));  // 第一次：没注册
  EXPECT_EQ(rejected.last().actor, QStringLiteral("DEV-003"));                     // 证书里的名称
  EXPECT_EQ(rejected.last().source, QStringLiteral("127.0.0.1"));
  EXPECT_TRUE(find(audit::kConn, QStringLiteral("设备登录")).isEmpty());
}
