// 设备登录与注册表、在线状态的联调（真实 TLS、真实 TcpServer / TcpClient）。
// 对应协议 5.1 节的 2005、2006、2007，以及测试报告 FT-01、FT-02、ST-04（停用部分）、ST-30。
#include <QJsonDocument>
#include <gtest/gtest.h>

#include "client/net/tcp_client.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using fwds_test::Identity;
using fwds_test::sharedPki;

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 300;
  p.reconnectBackoffMs = {30, 30};
  return p;
}

// 永远拒绝的许可证检查，用来验证接入点和 2006。
class RejectingLicense : public LicenseVerifier {
 public:
  QString check(const QString&, const QByteArray& license) override {
    lastLicense = license;
    return QStringLiteral("test: always invalid");
  }
  QByteArray lastLicense;
};

// 完整的服务端：网络层 + 登录裁决 + 在线状态同步 + 后台。默认只注册 DEV-001。
struct Server {
  explicit Server(LicenseVerifier* license = nullptr) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.maxConnectionsPerIp = 50;
    config.protocol = fastParams();
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol, &backend.registry, &backend.throttle,
                                           license);
    monitor = std::make_unique<HeartbeatMonitor>(server.get(), &backend.registry);
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
    });
    QObject::connect(server.get(), &TcpServer::sessionClosed,
                     [this](Session*, const QString& reason) { closeReasons.append(reason); });
    EXPECT_TRUE(server->start());
    backend.registerDevice(sharedPki().dev001, QStringLiteral("canary"));
  }
  DeviceRecord device(const QString& id = QStringLiteral("DEV-001")) {
    DeviceRecord d;
    backend.registry.find(id, &d);
    return d;
  }

  fwds_test::ServerBackend backend;
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  std::unique_ptr<HeartbeatMonitor> monitor;
  QStringList closeReasons;
};

// 一台设备：证书 + TcpClient，记录收到的登录失败码。
struct Device {
  Device(quint16 port, const Identity& identity, const QString& deviceId)
      : security(sharedPki().pki.security(identity)) {
    ClientConfig c;
    c.serverHost = QStringLiteral("127.0.0.1");
    c.serverPort = port;
    c.deviceId = deviceId;
    c.model = QStringLiteral("PLC-X200");
    c.protocol = fastParams();
    client = std::make_unique<TcpClient>(c, security.get());
    client->setLoginProvider([deviceId]() {
      QJsonObject o;
      o.insert(QStringLiteral("device_id"), deviceId);
      o.insert(QStringLiteral("model"), QStringLiteral("PLC-X200"));
      o.insert(QStringLiteral("fw_version"), QStringLiteral("2.0.0"));
      o.insert(QStringLiteral("security_version"), 4);
      o.insert(QStringLiteral("license"), QString::fromLatin1(QByteArray("lic-bytes").toBase64()));
      o.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
      return o;
    });
    QObject::connect(client.get(), &TcpClient::loginFailed, [this](int code) { codes.append(code); });
  }
  bool online() const { return client->state() == TcpClient::State::Online; }

  std::unique_ptr<TlsChannelSecurity> security;
  std::unique_ptr<TcpClient> client;
  QList<int> codes;
};

}  // namespace

// FT-01：已注册设备登录后，注册表里是在线、有地址和版本；心跳持续刷新“最后心跳”
TEST(DeviceLogin, RegisteredDeviceGoesOnlineAndHeartbeatsRefresh) {
  Server fx;
  Device dev(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.device().online; }));
  const DeviceRecord atLogin = fx.device();
  EXPECT_EQ(atLogin.peerAddress, QStringLiteral("127.0.0.1"));
  EXPECT_EQ(atLogin.currentVersion, QStringLiteral("2.0.0"));
  EXPECT_EQ(atLogin.securityVersion, 4);
  EXPECT_EQ(fx.backend.registry.onlineCount(), 1);

  ASSERT_TRUE(waitFor([&]() { return fx.device().lastHeartbeat > atLogin.lastHeartbeat; }));
}

// FT-02：设备进程被强制结束（不发 BYE）→ 连接断开后设备标记离线，最后心跳时间保留。
// 不断开连接、只是不再发心跳的情况由 Network 里的心跳超时用例覆盖，两条路径最后都走到会话关闭
TEST(DeviceLogin, DeviceGoesOfflineWhenConnectionDrops) {
  Server fx;
  auto dev = std::make_unique<Device>(fx.server->serverPort(), sharedPki().dev001,
                                      QStringLiteral("DEV-001"));
  dev->client->start();
  ASSERT_TRUE(waitFor([&]() { return fx.device().online; }));
  dev.reset();  // 相当于拔掉设备
  ASSERT_TRUE(waitFor([&]() { return !fx.device().online; }, 2000));
  EXPECT_EQ(fx.backend.registry.onlineCount(), 0);
  EXPECT_TRUE(fx.device().lastHeartbeat.isValid());
}

// 2005：证书是本 CA 签的、名称也对得上，但设备没有注册
TEST(DeviceLogin, UnregisteredDeviceGets2005) {
  Server fx;
  Device dev(fx.server->serverPort(), sharedPki().dev002, QStringLiteral("DEV-002"));
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return !dev.codes.isEmpty(); }));
  EXPECT_EQ(dev.codes.first(), 2005);
  ASSERT_TRUE(waitFor([&]() { return !fx.closeReasons.isEmpty(); }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("登录失败 2005"));
  EXPECT_EQ(fx.backend.registry.onlineCount(), 0);
}

// 2005：同一个设备 ID、同一个 CA，但不是注册时绑定的那张证书（指纹不符）
TEST(DeviceLogin, FingerprintMismatchGets2005AndRaisesAlert) {
  Server fx;
  const Identity other = sharedPki().pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  Device dev(fx.server->serverPort(), other, QStringLiteral("DEV-001"));
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return !dev.codes.isEmpty(); }));
  EXPECT_EQ(dev.codes.first(), 2005);
  EXPECT_FALSE(fx.device().online);
  EXPECT_FALSE(fx.device().alert.isEmpty());  // 界面上这一行标红
}

// ST-04（停用部分）：维护员停用设备 → 现有连接立即断开，重连得到 2005；其他设备不受影响
TEST(DeviceLogin, DisablingDeviceKicksItAndBlocksRelogin) {
  Server fx;
  fx.backend.registerDevice(sharedPki().dev002);
  Device dev1(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  Device dev2(fx.server->serverPort(), sharedPki().dev002, QStringLiteral("DEV-002"));
  dev1.client->start();
  dev2.client->start();
  ASSERT_TRUE(waitFor([&]() { return dev1.online() && dev2.online(); }));

  QString error;
  ASSERT_TRUE(fx.backend.admin.setDeviceDisabled(QStringLiteral("DEV-002"), true, &error));
  EXPECT_TRUE(fx.closeReasons.contains(QStringLiteral("设备已停用")));  // 立即断开，不等心跳超时
  EXPECT_FALSE(fx.device(QStringLiteral("DEV-002")).online);

  ASSERT_TRUE(waitFor([&]() { return !dev2.codes.isEmpty(); }));  // 客户端自动重连后被拒
  EXPECT_EQ(dev2.codes.first(), 2005);
  EXPECT_TRUE(dev1.online());
  EXPECT_TRUE(fx.device(QStringLiteral("DEV-001")).online);

  // 重新启用后可以再登录
  ASSERT_TRUE(fx.backend.admin.setDeviceDisabled(QStringLiteral("DEV-002"), false, &error));
  ASSERT_TRUE(waitFor([&]() { return dev2.online(); }));
}

// 2006：许可证检查的接入点。验证 LOGIN 里的 license 被 Base64 解码后交给 LicenseVerifier
TEST(DeviceLogin, LicenseVerifierRejectionGets2006) {
  RejectingLicense license;
  Server fx(&license);
  Device dev(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return !dev.codes.isEmpty(); }));
  EXPECT_EQ(dev.codes.first(), 2006);
  EXPECT_EQ(license.lastLicense, QByteArray("lic-bytes"));
  EXPECT_FALSE(fx.device().online);
}

// ST-30：同一设备连续登录失败 5 次后锁定；锁定期内换回正确的证书也是 2007
TEST(DeviceLogin, FiveFailuresLockDeviceWith2007) {
  Server fx;
  const Identity wrongCert = sharedPki().pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  {
    Device bad(fx.server->serverPort(), wrongCert, QStringLiteral("DEV-001"));
    bad.client->start();  // 客户端按退避自动重试，每次都是 2005
    ASSERT_TRUE(waitFor([&]() { return bad.codes.size() >= 5; }, 5000));
    EXPECT_EQ(bad.codes.mid(0, 5), (QList<int>{2005, 2005, 2005, 2005, 2005}));
  }
  Device good(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  good.client->start();
  ASSERT_TRUE(waitFor([&]() { return !good.codes.isEmpty(); }));
  EXPECT_EQ(good.codes.first(), 2007);
  EXPECT_FALSE(fx.device().online);
}

// 持有 DEV-002 证书的设备反复自称 DEV-001（2003）：失败记在证书里的 DEV-002 名下，
// 不能借此把 DEV-001 的设备 ID 锁住
TEST(DeviceLogin, ImpersonationFailuresAreCountedAgainstTheCertificateName) {
  Server fx;
  Device attacker(fx.server->serverPort(), sharedPki().dev002, QStringLiteral("DEV-001"));
  attacker.client->start();
  ASSERT_TRUE(waitFor([&]() { return attacker.codes.size() >= 5; }, 5000));
  attacker.client->stop();
  EXPECT_EQ(attacker.codes.first(), 2003);
  const qint64 now = QDateTime::currentMSecsSinceEpoch();
  EXPECT_TRUE(fx.backend.throttle.isLocked(QStringLiteral("id:DEV-002"), now));
  EXPECT_FALSE(fx.backend.throttle.isLocked(QStringLiteral("id:DEV-001"), now));
}

// 同一台设备用同一张证书再连一次（旧连接在服务端还没超时）：旧连接被断开，设备保持在线
TEST(DeviceLogin, SecondLoginReplacesFirstSession) {
  Server fx;
  Device first(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  first.client->start();
  ASSERT_TRUE(waitFor([&]() { return first.online(); }));

  Device second(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  second.client->start();
  ASSERT_TRUE(waitFor([&]() { return second.online(); }));
  EXPECT_TRUE(fx.closeReasons.contains(QStringLiteral("同一设备重新登录")));
  EXPECT_TRUE(fx.device().online);
  EXPECT_EQ(fx.backend.registry.onlineCount(), 1);
}

// 心跳里上报的升级状态和进度进入注册表（监控界面的“升级状态”“进度”两列）
TEST(DeviceLogin, HeartbeatStatusReachesRegistry) {
  Server fx;
  Device dev(fx.server->serverPort(), sharedPki().dev001, QStringLiteral("DEV-001"));
  dev.client->setHeartbeatProvider([]() {
    QJsonObject o;
    o.insert(QStringLiteral("state"), QStringLiteral("DOWNLOADING"));
    o.insert(QStringLiteral("progress"), 47);
    return o;
  });
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return fx.device().progress == 47; }));
  EXPECT_EQ(fx.device().upgradeState, QStringLiteral("DOWNLOADING"));
}
