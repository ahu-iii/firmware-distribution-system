// 单台下发的联调：真实 TLS、真实 TcpServer / TcpClient，服务端是
// 固件库 + RolloutManager + ChunkService，设备端是完整的升级状态机 Updater（A/B 分区、Bootloader）。
// 三个演示场景从“操作员点下发”一直走到设备给出结果：
//   正常升级（FT-04）、自检失败自动回滚（FT-13）、降级被拒（ST-21）。
// 另外覆盖下发前的裁决：“允许下发”开关（ST-24）、角色（ST-12）、离线设备不盲发、型号、
// 对升级中的设备再次推送（ST-25 ②）。
#include <QJsonObject>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/business/updater.h"
#include "client/net/tcp_client.h"
#include "server/business/chunk_service.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/login_handler.h"
#include "server/business/rollout_manager.h"
#include "server/net/tcp_server.h"
#include "tests/test_device.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 500;
  p.reconnectBackoffMs = {30, 30};
  p.chunkWindow = 4;
  p.chunkWindowTimeoutMs = 300;
  return p;
}

// 服务端：和 fwds-server 的 main 一样接线，只是没有界面。
struct Server {
  explicit Server(ServerBackend* backend) : backend(backend) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.maxConnectionsPerIp = 50;
    config.protocol = fastParams();
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol, &backend->registry, &backend->throttle);
    monitor = std::make_unique<HeartbeatMonitor>(server.get(), &backend->registry);
    chunks = std::make_unique<ChunkService>(server.get(), config.protocol);
    rollout = std::make_unique<RolloutManager>(&backend->db, config.protocol, &backend->registry,
                                               &backend->firmware, chunks.get(), &backend->gate);
    QString error;
    EXPECT_TRUE(rollout->load(&error)) << error.toStdString();
    backend->admin.setRolloutManager(rollout.get());
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
    });
    EXPECT_TRUE(server->start());
  }
  ~Server() { backend->admin.setRolloutManager(nullptr); }
  quint16 port() const { return server->serverPort(); }

  ServerBackend* backend;
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  std::unique_ptr<HeartbeatMonitor> monitor;
  std::unique_ptr<ChunkService> chunks;
  std::unique_ptr<RolloutManager> rollout;
};

// 一台设备：TcpClient + Updater，接线方式和 fwds-client 的 main 一样。出厂固件 2.0.0（安全版本号 4）。
struct Device {
  Device(quint16 port, const Identity& identity, const QString& deviceId, const QString& dataDir)
      : security(sharedPki().pki.security(identity)) {
    config.serverHost = QStringLiteral("127.0.0.1");
    config.serverPort = port;
    config.deviceId = deviceId;
    config.model = kTestModel;
    config.dataDir = dataDir;
    config.rebootDelayMs = 0;
    config.protocol = fastParams();
    const DeviceFirmware factory(QStringLiteral("2.0.0"), 4);
    factory.installTo(dataDir, QStringLiteral("a"));

    client = std::make_unique<TcpClient>(config, security.get());
    updater = std::make_unique<Updater>(
        config, verifier, [this](MsgType type, const QByteArray& body) { return client->send(type, body); });
    QObject::connect(client.get(), &TcpClient::frameReceived, updater.get(), &Updater::handleFrame);
    QObject::connect(client.get(), &TcpClient::stateChanged, updater.get(), [this](TcpClient::State s) {
      updater->setOnline(s == TcpClient::State::Online);
    });
    QObject::connect(updater.get(), &Updater::rebootRequested, client.get(),
                     [this]() { client->stop(QStringLiteral("reboot")); });
    QObject::connect(updater.get(), &Updater::rebootFinished, client.get(), [this]() { client->start(); });
    QObject::connect(updater.get(), &Updater::alertRaised,
                     [this](int code, const QString&) { alerts.append(code); });
    QObject::connect(updater.get(), &Updater::finished,
                     [this](const QString& result, int, const QString&) { results.append(result); });
    client->setLoginProvider([this]() {
      QJsonObject login = updater->loginFields();
      login.insert(QStringLiteral("device_id"), config.deviceId);
      login.insert(QStringLiteral("model"), config.model);
      login.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
      return login;
    });
    client->setHeartbeatProvider([this]() {
      QJsonObject hb;
      hb.insert(QStringLiteral("state"), updater->stateName());
      hb.insert(QStringLiteral("progress"), updater->progress());
      return hb;
    });
    updater->powerOn();
    client->start();
  }
  QString runningVersion() const { return updater->bootState().running.version; }

  ClientConfig config;
  std::unique_ptr<TlsChannelSecurity> security;
  ManifestVerifier verifier = trustedVerifier();
  std::unique_ptr<TcpClient> client;
  std::unique_ptr<Updater> updater;
  QList<int> alerts;
  QStringList results;
};

class Dispatch : public ::testing::Test {
 protected:
  Dispatch() { backend.registerDevice(sharedPki().dev001); }

  // 做一个固件包并以维护员身份导入固件库，返回包 ID。
  QString importFirmware(const QString& version, int securityVersion, bool selfTestFails = false,
                         const QString& model = kTestModel) {
    const DeviceFirmware fw(version, securityVersion, 5 * kChunkSize + 77, selfTestFails, model);
    Manifest manifest;
    const QString path = packageFileFor(fw, dir.path(), QStringLiteral("fw-") + version, &manifest);
    backend.importFirmware(path);
    return manifest.pkgId;
  }
  // 设备已登录，并且至少上报过一次心跳（服务端知道它的升级状态）。
  bool deviceReady(const QString& deviceId = QStringLiteral("DEV-001")) {
    return waitFor([&]() {
      DeviceRecord record;
      return backend.registry.find(deviceId, &record) && record.online &&
             !record.upgradeState.isEmpty();
    });
  }
  // 设备表里这台设备的升级状态（来自心跳）。
  QString reportedState() {
    DeviceRecord record;
    backend.registry.find(kDev1, &record);
    return record.upgradeState;
  }
  int releaseRows() {
    QSqlQuery query(backend.db.handle());
    query.exec(QStringLiteral("SELECT COUNT(*) FROM \"release\""));
    return query.next() ? query.value(0).toInt() : -1;
  }

  const QString kDev1 = QStringLiteral("DEV-001");
  QTemporaryDir dir;
  ServerBackend backend;
  QString error;
};

}  // namespace

// FT-04：操作员下发 2.1.0 → 设备验签、下载、写入备用分区、重启、转正；
// 设备重新登录后服务端看到新版本，发布表里留下这次下发的记录
TEST_F(Dispatch, OperatorDispatchUpgradesDevice) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();

  ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return dev.updater->state() == Updater::State::Success; }, 15000));
  EXPECT_EQ(dev.runningVersion(), QStringLiteral("2.1.0"));
  EXPECT_EQ(dev.updater->bootState().config.active, QStringLiteral("b"));
  EXPECT_EQ(dev.results, QStringList{QStringLiteral("SUCCESS")});

  // 设备模拟重启后重新登录，带上了新的版本号；心跳里的状态是 SUCCESS
  DeviceRecord record;
  ASSERT_TRUE(waitFor([&]() {
    backend.registry.find(kDev1, &record);
    return record.online && record.currentVersion == QStringLiteral("2.1.0") &&
           record.upgradeState == QStringLiteral("SUCCESS");
  }, 5000));
  EXPECT_EQ(record.securityVersion, 5);

  const QList<DispatchRecord> records = fx.rollout->recentDispatches(10);
  ASSERT_EQ(records.size(), 1);
  EXPECT_EQ(records.first().pkgId, pkgId);
  EXPECT_EQ(records.first().deviceId, kDev1);
  EXPECT_EQ(records.first().createdBy, QStringLiteral("oper"));
  EXPECT_EQ(records.first().releaseState, QStringLiteral("canary"));
  EXPECT_EQ(records.first().targetStatus, QStringLiteral("notified"));
}

// FT-13：下发一份“自检必定失败”的固件 → 设备写入、重启、自检不过、自动回到原分区，
// 仍然运行 2.0.0；服务端在心跳里看到 ROLLED_BACK
TEST_F(Dispatch, SelfTestFailureRollsBackAndServerSeesIt) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5, true);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();

  ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return dev.updater->state() == Updater::State::RolledBack; }, 15000));
  EXPECT_EQ(dev.runningVersion(), QStringLiteral("2.0.0"));
  EXPECT_EQ(dev.updater->bootState().config.active, QStringLiteral("a"));
  EXPECT_EQ(dev.results, QStringList{QStringLiteral("ROLLED_BACK")});

  DeviceRecord record;
  ASSERT_TRUE(waitFor([&]() {
    backend.registry.find(kDev1, &record);
    return record.online && record.upgradeState == QStringLiteral("ROLLED_BACK");
  }, 5000));
  EXPECT_EQ(record.currentVersion, QStringLiteral("2.0.0"));
  // 设备重新登录后服务端会重发同一个包的通知，设备不会再装一遍
  spin(300);
  EXPECT_EQ(dev.updater->state(), Updater::State::RolledBack);
  EXPECT_EQ(dev.results.size(), 1);
}

// ST-21：服务端下发一份签名合法的旧固件（1.9.0，安全版本号 3）。服务端不拦——防降级由设备把关：
// 设备用 3003 拒绝，一个分片都不下载，继续运行 2.0.0
TEST_F(Dispatch, DowngradeIsRejectedByDevice) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("1.9.0"), 3);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();

  ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return dev.updater->state() == Updater::State::Failed; }, 5000));
  EXPECT_EQ(dev.alerts, QList<int>{static_cast<int>(ErrorCode::RollbackAttempt)});
  EXPECT_EQ(fx.chunks->chunksSent(), 0);
  EXPECT_EQ(dev.runningVersion(), QStringLiteral("2.0.0"));
  ASSERT_TRUE(waitFor([&]() { return reportedState() == QStringLiteral("FAILED"); }, 3000));
}

// ST-24：“允许下发”开关默认关闭，关着的时候操作员下发被拒，设备什么都收不到，数据库里也没有记录
TEST_F(Dispatch, RejectedWhileGateIsClosed) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();
  // 维护员把开关关掉，再换回操作员
  backend.loginAsMaintainer();
  ASSERT_TRUE(backend.admin.setDispatchEnabled(false, &error));
  ASSERT_EQ(backend.admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &error), AuthResult::Ok);

  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, kDev1, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("允许下发"))) << error.toStdString();
  spin(200);
  EXPECT_EQ(dev.updater->state(), Updater::State::Idle);
  EXPECT_TRUE(fx.chunks->assignedPackage(kDev1).isEmpty());
  EXPECT_EQ(releaseRows(), 0);
}

// ST-12：下发只有操作员能做。维护员（能开开关的人）自己不能下发，没登录更不行
TEST_F(Dispatch, OnlyOperatorCanDispatch) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.loginAsMaintainer();
  ASSERT_TRUE(backend.admin.setDispatchEnabled(true, &error));

  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, kDev1, &error));
  backend.admin.logout();
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, kDev1, &error));
  EXPECT_TRUE(fx.chunks->assignedPackage(kDev1).isEmpty());
  EXPECT_EQ(releaseRows(), 0);
}

// 下发前的其余裁决：离线设备、没注册的设备、已停用的设备、型号不符、不存在的包，都被拒且不留记录
TEST_F(Dispatch, RejectsOfflineUnknownDisabledAndWrongModel) {
  Server fx(&backend);
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  const QString otherModel = importFirmware(QStringLiteral("3.0.0"), 6, false, QStringLiteral("HMI-7"));
  backend.registerDevice(sharedPki().dev002);
  backend.openGateAndLoginAsOperator();

  // DEV-001 已注册但还没上线：不下发，之后上线也不会收到通知（不缓存、不盲发）
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, kDev1, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("不在线"))) << error.toStdString();
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, QStringLiteral("DEV-999"), &error));

  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  spin(200);
  EXPECT_EQ(dev.updater->state(), Updater::State::Idle);

  EXPECT_FALSE(backend.admin.dispatchFirmware(otherModel, kDev1, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("型号"))) << error.toStdString();
  EXPECT_FALSE(backend.admin.dispatchFirmware(QStringLiteral("no-such-package"), kDev1, &error));

  // 停用 DEV-002 之后（它本来也不在线）同样被拒
  backend.loginAsMaintainer();
  ASSERT_TRUE(backend.admin.setDeviceDisabled(QStringLiteral("DEV-002"), true, &error));
  ASSERT_EQ(backend.admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &error), AuthResult::Ok);
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgId, QStringLiteral("DEV-002"), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("停用"))) << error.toStdString();

  EXPECT_EQ(releaseRows(), 0);
}

// ST-25 ②：设备正在升级时不能再下发；刚下发过、设备还没上报新状态时也不能
TEST_F(Dispatch, BusyDeviceIsNotDispatchedAgain) {
  Server fx(&backend);
  const QString first = importFirmware(QStringLiteral("2.1.0"), 5);
  const QString second = importFirmware(QStringLiteral("2.2.0"), 6);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(deviceReady());
  backend.openGateAndLoginAsOperator();

  ASSERT_TRUE(backend.admin.dispatchFirmware(first, kDev1, &error)) << error.toStdString();
  // 紧接着再下发另一个包：被拒，第一个包的下发不受影响
  EXPECT_FALSE(backend.admin.dispatchFirmware(second, kDev1, &error));
  EXPECT_EQ(fx.chunks->assignedPackage(kDev1), first);
  EXPECT_EQ(releaseRows(), 1);

  ASSERT_TRUE(waitFor([&]() { return dev.updater->state() == Updater::State::Success; }, 15000));
  EXPECT_EQ(dev.runningVersion(), QStringLiteral("2.1.0"));
  // 升级完成、设备上报 SUCCESS，并且离上次下发已经过了两个心跳间隔之后，才可以下发下一个包
  ASSERT_TRUE(waitFor([&]() { return reportedState() == QStringLiteral("SUCCESS"); }, 5000));
  spin(3 * fastParams().heartbeatIntervalMs);
  ASSERT_TRUE(backend.admin.dispatchFirmware(second, kDev1, &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return dev.runningVersion() == QStringLiteral("2.2.0"); }, 15000));
}

// 服务端重启：上次还在推送中的发布变成“已暂停”，不会自动接着推（设计 4.7 节）
TEST_F(Dispatch, InProgressReleaseIsPausedAfterServerRestart) {
  const QString pkgId = importFirmware(QStringLiteral("2.1.0"), 5);
  {
    Server fx(&backend);
    Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
    ASSERT_TRUE(deviceReady());
    backend.openGateAndLoginAsOperator();
    ASSERT_TRUE(backend.admin.dispatchFirmware(pkgId, kDev1, &error)) << error.toStdString();
  }
  Server restarted(&backend);  // 新的 ChunkService 和 RolloutManager，数据库还是同一个
  const QList<DispatchRecord> records = restarted.rollout->recentDispatches(10);
  ASSERT_EQ(records.size(), 1);
  EXPECT_EQ(records.first().releaseState, QStringLiteral("paused"));
  EXPECT_TRUE(restarted.chunks->assignedPackage(kDev1).isEmpty());
}
