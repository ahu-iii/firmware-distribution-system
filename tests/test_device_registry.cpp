// 设备注册表：注册、指纹核对、在线状态、落盘。
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/crypto/x509_util.h"
#include "tests/test_server_env.h"

using namespace fwds;
using fwds_test::ServerBackend;
using fwds_test::sharedPki;

namespace {
QString fingerprintOf(const fwds_test::Identity& id) {
  return certFingerprintSha256(certFromPem(id.certPem).get());
}
}  // namespace

// 注册时设备 ID、指纹、到期时间都从证书里取
TEST(DeviceRegistry, RegisterTakesIdAndFingerprintFromCertificate) {
  ServerBackend be;
  be.registerDevice(sharedPki().dev001, QStringLiteral("canary"));
  DeviceRecord d;
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-001"), &d));
  EXPECT_EQ(d.model, QStringLiteral("PLC-X200"));
  EXPECT_EQ(d.groupTag, QStringLiteral("canary"));
  EXPECT_EQ(d.certFingerprint, fingerprintOf(sharedPki().dev001));
  EXPECT_EQ(d.certFingerprint.size(), 64);
  EXPECT_TRUE(d.certNotAfter.isValid());
  EXPECT_FALSE(d.disabled);
  EXPECT_FALSE(d.online);
}

// 登录检查的四种结果
TEST(DeviceRegistry, CheckLoginDistinguishesTheThreeFailures) {
  ServerBackend be;
  be.registerDevice(sharedPki().dev001);
  const QString fp1 = fingerprintOf(sharedPki().dev001);
  const QString fp2 = fingerprintOf(sharedPki().dev002);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fp1), DeviceCheck::Ok);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fp1.toUpper()), DeviceCheck::Ok);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-002"), fp2), DeviceCheck::NotRegistered);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fp2), DeviceCheck::FingerprintMismatch);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), QString()),
            DeviceCheck::FingerprintMismatch);
  QString error;
  ASSERT_TRUE(be.admin.setDeviceDisabled(QStringLiteral("DEV-001"), true, &error));
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fp1), DeviceCheck::Disabled);
  ASSERT_TRUE(be.admin.setDeviceDisabled(QStringLiteral("DEV-001"), false, &error));
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fp1), DeviceCheck::Ok);
}

// 证书轮换：同一个设备 ID 重新注册新证书，旧指纹失效，其他字段保留
TEST(DeviceRegistry, ReRegisterReplacesFingerprint) {
  ServerBackend be;
  be.registerDevice(sharedPki().dev001, QStringLiteral("canary"));
  be.registry.markOnline(QStringLiteral("DEV-001"), QStringLiteral("127.0.0.1"),
                         QStringLiteral("2.0.0"), 4);
  const fwds_test::Identity renewed =
      sharedPki().pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  be.registerDevice(renewed, QStringLiteral("canary"));
  EXPECT_EQ(be.registry.devices().size(), 1);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fingerprintOf(renewed)),
            DeviceCheck::Ok);
  EXPECT_EQ(be.registry.checkLogin(QStringLiteral("DEV-001"), fingerprintOf(sharedPki().dev001)),
            DeviceCheck::FingerprintMismatch);
  DeviceRecord d;
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-001"), &d));
  EXPECT_EQ(d.currentVersion, QStringLiteral("2.0.0"));
}

TEST(DeviceRegistry, OnlineStateAndSignals) {
  ServerBackend be;
  be.registerDevice(sharedPki().dev001);
  QStringList changed;
  QObject::connect(&be.registry, &DeviceRegistry::deviceChanged,
                   [&](const QString& id) { changed.append(id); });

  be.registry.raiseAlert(QStringLiteral("DEV-001"), QStringLiteral("证书指纹与注册表不符"));
  be.registry.markOnline(QStringLiteral("DEV-001"), QStringLiteral("10.0.0.7"),
                         QStringLiteral("2.0.0"), 4);
  be.registry.markHeartbeat(QStringLiteral("DEV-001"), QStringLiteral("DOWNLOADING"), 47);
  DeviceRecord d;
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-001"), &d));
  EXPECT_TRUE(d.online);
  EXPECT_TRUE(d.alert.isEmpty());  // 登录成功后告警清除
  EXPECT_EQ(d.peerAddress, QStringLiteral("10.0.0.7"));
  EXPECT_EQ(d.upgradeState, QStringLiteral("DOWNLOADING"));
  EXPECT_EQ(d.progress, 47);
  EXPECT_EQ(be.registry.onlineCount(), 1);

  be.registry.markOffline(QStringLiteral("DEV-001"));
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-001"), &d));
  EXPECT_FALSE(d.online);
  EXPECT_EQ(be.registry.onlineCount(), 0);
  EXPECT_EQ(changed.size(), 4);

  // 未注册的设备 ID：什么都不做，也不会凭空多出一行
  be.registry.markOnline(QStringLiteral("DEV-999"), QStringLiteral("10.0.0.8"), QString(), 0);
  EXPECT_EQ(be.registry.devices().size(), 1);
}

// 注册信息落盘：重启后还在；上次留下的“在线”被改回离线；停用状态保留
TEST(DeviceRegistry, PersistsAcrossRestartAndResetsOnline) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("sub/dir/server.db"));  // 目录不存在时自动创建
  {
    ServerBackend be(path);
    be.registerDevice(sharedPki().dev001, QStringLiteral("canary"));
    be.registerDevice(sharedPki().dev002);
    QString error;
    ASSERT_TRUE(be.admin.setDeviceDisabled(QStringLiteral("DEV-002"), true, &error));
    be.registry.markOnline(QStringLiteral("DEV-001"), QStringLiteral("127.0.0.1"),
                           QStringLiteral("2.0.0"), 4);
    // 不调 markOffline，模拟服务端被强制结束
  }
  ServerBackend be(path);
  ASSERT_EQ(be.registry.devices().size(), 2);
  DeviceRecord d1, d2;
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-001"), &d1));
  ASSERT_TRUE(be.registry.find(QStringLiteral("DEV-002"), &d2));
  EXPECT_FALSE(d1.online);
  EXPECT_EQ(d1.groupTag, QStringLiteral("canary"));
  EXPECT_EQ(d1.currentVersion, QStringLiteral("2.0.0"));
  EXPECT_EQ(d1.securityVersion, 4);
  EXPECT_TRUE(d1.lastHeartbeat.isValid());
  EXPECT_EQ(d1.certFingerprint, fingerprintOf(sharedPki().dev001));
  EXPECT_TRUE(d2.disabled);
}
