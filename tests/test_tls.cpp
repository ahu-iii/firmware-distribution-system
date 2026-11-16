// TLS 双向认证的联调测试：在本机回环上用真实的 TcpServer / TcpClient 和现签的证书，
// 对应测试报告 ST-01 ~ ST-05、ST-10 的自动化部分（现场取证时再用 openssl s_client 和抓包各做一遍）。
#include <QFile>
#include <QJsonDocument>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTemporaryDir>
#include <QTcpServer>
#include <gtest/gtest.h>

#include "client/net/tcp_client.h"
#include "common/crypto/key_file.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "tests/test_pki.h"
#include "tests/test_util.h"

using namespace fwds;
using fwds_test::Identity;
using fwds_test::sharedPki;
using fwds_test::TestPki;

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 300;
  p.reconnectBackoffMs = {50, 100, 200};
  return p;
}

// 服务端 + 登录处理，记录每个会话是怎么结束的。
struct TlsServer {
  explicit TlsServer(std::unique_ptr<TlsChannelSecurity> sec = nullptr)
      : security(sec ? std::move(sec) : sharedPki().pki.security(sharedPki().server)) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.maxConnectionsPerIp = 50;
    config.protocol = fastParams();
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol);
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
      QObject::connect(s, &Session::stateChanged, [this](Session* changed) {
        if (changed->state() == Session::State::WaitLogin) ++reachedWaitLogin;
        if (changed->state() == Session::State::Online) ++reachedOnline;
      });
    });
    QObject::connect(server.get(), &TcpServer::sessionClosed,
                     [this](Session*, const QString& reason) { closeReasons.append(reason); });
    EXPECT_TRUE(server->start());
  }
  quint16 port() const { return server->serverPort(); }

  std::unique_ptr<TlsChannelSecurity> security;
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  int reachedWaitLogin = 0;  // 握手和证书补充校验都通过的会话数
  int reachedOnline = 0;
  QStringList closeReasons;
};

ClientConfig clientConfig(quint16 port, const QString& deviceId = QStringLiteral("DEV-001"),
                          const QString& host = QStringLiteral("127.0.0.1")) {
  ClientConfig c;
  c.serverHost = host;
  c.serverPort = port;
  c.deviceId = deviceId;
  c.model = QStringLiteral("PLC-X200");
  c.protocol = fastParams();
  return c;
}

void useLogin(TcpClient& client, const QString& deviceId) {
  client.setLoginProvider([deviceId]() {
    QJsonObject o;
    o.insert(QStringLiteral("device_id"), deviceId);
    o.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
    return o;
  });
}

// 不经过 TlsChannelSecurity、直接手工配置的 TLS 客户端：用来模拟“不按规矩来”的对端
// （不带证书、带过期证书、用低版本协议、用别的套件）。
struct RawTlsClient {
  RawTlsClient(const QByteArray& caPem, const Identity* identity,
               QSsl::SslProtocol protocol = QSsl::TlsV1_3, const QString& cipher = QString()) {
    QSslConfiguration config = socket.sslConfiguration();
    config.setProtocol(protocol);
    config.setCaCertificates({QSslCertificate(caPem, QSsl::Pem)});
    if (!cipher.isEmpty()) config.setCiphers({QSslCipher(cipher)});
    if (identity) {
      const QByteArray der = QByteArray::fromRawData(
          reinterpret_cast<const char*>(identity->keyPkcs8.data()), identity->keyPkcs8.size());
      const QByteArray pem =
          "-----BEGIN PRIVATE KEY-----\n" + der.toBase64() + "\n-----END PRIVATE KEY-----\n";
      config.setLocalCertificate(QSslCertificate(identity->certPem, QSsl::Pem));
      config.setPrivateKey(QSslKey(pem, QSsl::Ec, QSsl::Pem));
    }
    socket.setSslConfiguration(config);
    QObject::connect(&socket, &QSslSocket::encrypted, [this]() { encrypted = true; });
    QObject::connect(&socket, &QAbstractSocket::disconnected, [this]() { disconnected = true; });
    QObject::connect(&socket, &QAbstractSocket::errorOccurred, [this]() { disconnected = true; });
  }
  void connectTo(quint16 port) {
    socket.connectToHostEncrypted(QStringLiteral("127.0.0.1"), port);
  }
  QSslSocket socket;
  bool encrypted = false;
  bool disconnected = false;
};

// 假服务端：能做 TLS 握手，记录握手是否完成、是否收到过任何应用数据。
class FakeServer : public QTcpServer {
 public:
  explicit FakeServer(std::unique_ptr<TlsChannelSecurity> security) : security_(std::move(security)) {}
  int handshakes = 0;
  qint64 bytesReceived = 0;

 protected:
  void incomingConnection(qintptr descriptor) override {
    auto* socket = new QSslSocket(this);
    socket->setSocketDescriptor(descriptor);
    security_->prepare(socket, true);
    connect(socket, &QSslSocket::encrypted, this, [this]() { ++handshakes; });
    connect(socket, &QSslSocket::readyRead, this,
            [this, socket]() { bytesReceived += socket->readAll().size(); });
    socket->startServerEncryption();
  }

 private:
  std::unique_ptr<TlsChannelSecurity> security_;
};

// 启动客户端并等它被拒绝（进入退避），返回第一次重连的原因。期间不应登录成功。
QString expectClientRejected(TcpClient& client) {
  QStringList reasons;
  bool loggedIn = false;
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int, const QString& reason) { reasons.append(reason); });
  QObject::connect(&client, &TcpClient::loggedIn, [&]() { loggedIn = true; });
  client.start();
  EXPECT_TRUE(waitFor([&]() { return !reasons.isEmpty(); }));
  EXPECT_FALSE(loggedIn);
  client.stop();
  return reasons.value(0);
}

}  // namespace

// ---------- 正常连接 ----------

// ST-05 的正面部分：正常连接协商出来的就是 TLS 1.3 + TLS_AES_256_GCM_SHA384，双方都拿到了对方的证书
TEST(Tls, HandshakeUsesTls13Aes256GcmWithMutualCerts) {
  TlsServer fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  RawTlsClient peer(sharedPki().pki.caPem(), nullptr);
  security->prepare(&peer.socket, false);  // 用产品代码的配置握手，再从 socket 上读协商结果
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return peer.encrypted; }));
  EXPECT_EQ(peer.socket.sessionProtocol(), QSsl::TlsV1_3);
  EXPECT_EQ(peer.socket.sessionCipher().name(), QStringLiteral("TLS_AES_256_GCM_SHA384"));
  EXPECT_EQ(peer.socket.sessionCipher().usedBits(), 256);
  EXPECT_FALSE(peer.socket.peerCertificate().isNull());

  PeerIdentity serverIdentity;
  EXPECT_EQ(security->verifyPeer(&peer.socket, false, &serverIdentity), QString());
  EXPECT_EQ(serverIdentity.name, QStringLiteral("127.0.0.1"));

  // 服务端一侧也完成了对设备证书的校验，并记下了证书里的设备 ID
  ASSERT_TRUE(waitFor([&]() { return fx.reachedWaitLogin == 1; }));
  EXPECT_EQ(fx.server->sessions().first()->peerIdentity().name, QStringLiteral("DEV-001"));
  EXPECT_EQ(fx.server->sessions().first()->peerIdentity().fingerprint.size(), 64);
}

TEST(Tls, DeviceLogsInOverMutualTls) {
  TlsServer fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fx.port()), security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  client.start();
  ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));
  EXPECT_EQ(fx.reachedOnline, 1);
}

// ---------- ST-01 / ST-02：双向认证 ----------

// ST-01：客户端不出示证书，握手失败，服务端不进入等待登录状态
TEST(Tls, ClientWithoutCertificateIsRejected) {
  TlsServer fx;
  RawTlsClient peer(sharedPki().pki.caPem(), nullptr);
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_EQ(fx.reachedWaitLogin, 0);
  EXPECT_TRUE(waitFor([&]() { return peer.disconnected; }));
}

// ST-02：伪造的服务端（证书由别的 CA 签发）。客户端握手失败，不发送任何业务数据
TEST(Tls, ClientRejectsServerFromOtherCa) {
  TestPki evil;
  FakeServer fake(evil.security(evil.issue(CertType::Server, QStringLiteral("127.0.0.1"))));
  ASSERT_TRUE(fake.listen(QHostAddress::LocalHost, 0));

  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fake.serverPort()), security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  const QString reason = expectClientRejected(client);
  EXPECT_TRUE(reason.startsWith(QStringLiteral("网络错误"))) << reason.toStdString();
  spin(100);
  EXPECT_EQ(fake.handshakes, 0);
  EXPECT_EQ(fake.bytesReceived, 0);  // LOGIN 没有发出去
}

// 用途绑定：一台设备拿自己的（合法）设备证书冒充服务端，客户端同样拒绝
TEST(Tls, ClientRejectsDeviceCertUsedAsServer) {
  FakeServer fake(sharedPki().pki.security(sharedPki().dev002));
  ASSERT_TRUE(fake.listen(QHostAddress::LocalHost, 0));
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fake.serverPort()), security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  expectClientRejected(client);
  spin(100);
  EXPECT_EQ(fake.bytesReceived, 0);
}

// ---------- ST-03：证书链、有效期、名称 ----------

TEST(Tls, DeviceCertFromOtherCaIsRejected) {
  TlsServer fx;
  TestPki evil;
  const Identity forged = evil.issue(CertType::Device, QStringLiteral("DEV-001"));
  // 伪造者信任真 CA（为了能验过服务端），但自己的证书是假 CA 签的
  RawTlsClient peer(sharedPki().pki.caPem(), &forged);
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_EQ(fx.reachedWaitLogin, 0);
}

TEST(Tls, ExpiredDeviceCertIsRejected) {
  TlsServer fx;
  const QDateTime now = QDateTime::currentDateTimeUtc();
  const Identity expired = sharedPki().pki.issue(CertType::Device, QStringLiteral("DEV-001"),
                                                 now.addDays(-10), now.addSecs(-60));
  RawTlsClient peer(sharedPki().pki.caPem(), &expired);
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_EQ(fx.reachedWaitLogin, 0);
}

// 有效期超过上限的证书：链和时间都没问题，握手能过，但补充校验把它拒掉
TEST(Tls, OverlongDeviceCertIsRejectedAfterHandshake) {
  TlsServer fx;
  const QDateTime now = QDateTime::currentDateTimeUtc();
  const Identity longLived = sharedPki().pki.issue(CertType::Device, QStringLiteral("DEV-001"),
                                                   now.addSecs(-300), now.addDays(200));
  RawTlsClient peer(sharedPki().pki.caPem(), &longLived);
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("证书校验失败"));
  EXPECT_EQ(fx.reachedWaitLogin, 0);
}

// 服务端证书名称与客户端配置的地址不符：证书是签给 127.0.0.1 的，客户端按 localhost 去连
TEST(Tls, ClientRejectsServerNameMismatch) {
  TlsServer fx;
  const auto security =
      sharedPki().pki.security(sharedPki().dev001, QStringLiteral("localhost"));
  TcpClient client(clientConfig(fx.port(), QStringLiteral("DEV-001"), QStringLiteral("localhost")),
                   security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  expectClientRejected(client);
  EXPECT_EQ(fx.reachedOnline, 0);
}

// ST-10：用 DEV-002 的证书登录，LOGIN 里自称 DEV-001 → 2003
TEST(Tls, LoginDeviceIdMustMatchCertificateName) {
  TlsServer fx;
  const auto security = sharedPki().pki.security(sharedPki().dev002);
  TcpClient client(clientConfig(fx.port()), security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  QList<int> codes;
  QObject::connect(&client, &TcpClient::loginFailed, [&](int code) { codes.append(code); });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return !codes.isEmpty(); }));
  EXPECT_EQ(codes.first(), 2003);
  EXPECT_EQ(fx.reachedOnline, 0);
  ASSERT_TRUE(waitFor([&]() { return !fx.closeReasons.isEmpty(); }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("登录失败 2003"));
}

// ---------- ST-04：吊销 ----------

// 服务端导入吊销了 DEV-002 的新 CRL：DEV-002 重连被拒，DEV-001 不受影响
TEST(Tls, RevokedDeviceIsRejectedOthersUnaffected) {
  TestPki pki;
  const Identity server = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  const Identity dev1 = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  const Identity dev2 = pki.issue(CertType::Device, QStringLiteral("DEV-002"));
  TlsServer fx(pki.security(server));

  const auto sec2 = pki.security(dev2);
  TcpClient client2(clientConfig(fx.port(), QStringLiteral("DEV-002")), sec2.get());
  useLogin(client2, QStringLiteral("DEV-002"));
  client2.start();
  ASSERT_TRUE(waitFor([&]() { return client2.state() == TcpClient::State::Online; }));
  client2.stop();
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));

  QString error;
  ASSERT_TRUE(fx.security->reloadCrl(pki.crl({dev2.serialHex}), &error)) << error.toStdString();

  TcpClient again(clientConfig(fx.port(), QStringLiteral("DEV-002")), sec2.get());
  useLogin(again, QStringLiteral("DEV-002"));
  expectClientRejected(again);
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() >= 2; }));
  EXPECT_EQ(fx.closeReasons.at(1), QStringLiteral("证书校验失败"));
  EXPECT_EQ(fx.reachedOnline, 1);  // 只有吊销前的那一次

  const auto sec1 = pki.security(dev1);
  TcpClient client1(clientConfig(fx.port()), sec1.get());
  useLogin(client1, QStringLiteral("DEV-001"));
  client1.start();
  ASSERT_TRUE(waitFor([&]() { return client1.state() == TcpClient::State::Online; }));
}

// 反方向：服务端证书被吊销（私钥泄露的场景），拿到新 CRL 的设备不再连它
TEST(Tls, ClientRejectsRevokedServerCertificate) {
  TestPki pki;
  const Identity server = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  const Identity dev1 = pki.issue(CertType::Device, QStringLiteral("DEV-001"));
  TlsServer fx(pki.security(server));
  const auto security = pki.security(dev1);
  QString error;
  ASSERT_TRUE(security->reloadCrl(pki.crl({server.serialHex}), &error));

  TcpClient client(clientConfig(fx.port()), security.get());
  useLogin(client, QStringLiteral("DEV-001"));
  EXPECT_EQ(expectClientRejected(client), QStringLiteral("服务端证书校验失败"));
  EXPECT_EQ(fx.reachedOnline, 0);
}

// 从文件加载（程序实际走的路径）：私钥文件要用口令解开；CRL 文件被替换后，下一次握手自动生效
TEST(Tls, LoadsFromFilesAndPicksUpNewCrlFile) {
  TestPki pki;
  const Identity server = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  const Identity dev2 = pki.issue(CertType::Device, QStringLiteral("DEV-002"));

  QTemporaryDir dir;
  const auto write = [&dir](const char* name, const QByteArray& content) {
    QFile file(dir.filePath(QString::fromLatin1(name)));
    EXPECT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(content);
    return file.fileName();
  };
  const QByteArray pass = "file-based-test-passphrase";
  const SecureBuffer passphrase = SecureBuffer::fromBytes(pass.constData(), static_cast<int>(pass.size()));
  QByteArray sealed;
  QString error;
  ASSERT_TRUE(sealPrivateKey(server.keyPkcs8, passphrase, &sealed, &error, kKeyFileMinIterations));

  TlsConfig files;
  files.caFile = write("ca.pem", pki.caPem());
  files.crlFile = write("crl.pem", pki.crl());
  files.certFile = write("server.pem", server.certPem);
  files.keyFile = write("server.key", sealed);

  // 口令不对就加载不了
  const QByteArray wrong = "not-the-right-passphrase";
  auto bad = std::make_unique<TlsChannelSecurity>();
  EXPECT_FALSE(bad->loadFiles(
      files, SecureBuffer::fromBytes(wrong.constData(), static_cast<int>(wrong.size())), &error));

  auto serverSecurity = std::make_unique<TlsChannelSecurity>();
  ASSERT_TRUE(serverSecurity->loadFiles(files, passphrase, &error)) << error.toStdString();
  EXPECT_EQ(serverSecurity->localIdentity().name, QStringLiteral("127.0.0.1"));
  TlsServer fx(std::move(serverSecurity));

  const auto sec2 = pki.security(dev2);
  {
    TcpClient client(clientConfig(fx.port(), QStringLiteral("DEV-002")), sec2.get());
    useLogin(client, QStringLiteral("DEV-002"));
    client.start();
    ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));
    client.stop();
  }

  spin(20);  // 让新文件的修改时间和旧文件不同
  write("crl.pem", pki.crl({dev2.serialHex}));
  TcpClient again(clientConfig(fx.port(), QStringLiteral("DEV-002")), sec2.get());
  useLogin(again, QStringLiteral("DEV-002"));
  expectClientRejected(again);
  EXPECT_EQ(fx.reachedOnline, 1);
  EXPECT_TRUE(fx.closeReasons.contains(QStringLiteral("证书校验失败")));
}

// 本端证书和私钥不是一对、本端证书已过期：加载阶段就报错，程序不会带着坏材料启动
TEST(Tls, LoadRejectsMismatchedKeyAndExpiredCert) {
  TestPki& pki = sharedPki().pki;
  QString error;
  TlsChannelSecurity mismatched;
  EXPECT_FALSE(mismatched.load(pki.caPem(), pki.crl(), sharedPki().dev001.certPem,
                               sharedPki().dev002.keyPkcs8, &error));
  const QDateTime now = QDateTime::currentDateTimeUtc();
  const Identity expired =
      pki.issue(CertType::Device, QStringLiteral("DEV-001"), now.addDays(-10), now.addSecs(-60));
  TlsChannelSecurity old;
  EXPECT_FALSE(old.load(pki.caPem(), pki.crl(), expired.certPem, expired.keyPkcs8, &error));
}

// ---------- ST-05：协议版本与套件 ----------

TEST(Tls, Tls12ClientIsRejected) {
  TlsServer fx;
  RawTlsClient peer(sharedPki().pki.caPem(), &sharedPki().dev001, QSsl::TlsV1_2);
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_FALSE(peer.encrypted);
  EXPECT_EQ(fx.reachedWaitLogin, 0);
}

class OtherCipherTest : public ::testing::TestWithParam<const char*> {};

// 只提供其他套件的客户端（即使同样是 TLS 1.3、同样带合法证书）握手失败
TEST_P(OtherCipherTest, ClientOfferingOnlyOtherSuiteIsRejected) {
  TlsServer fx;
  RawTlsClient peer(sharedPki().pki.caPem(), &sharedPki().dev001, QSsl::TlsV1_3,
                    QString::fromLatin1(GetParam()));
  peer.connectTo(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_FALSE(peer.encrypted);
  EXPECT_EQ(fx.reachedWaitLogin, 0);
}

INSTANTIATE_TEST_SUITE_P(Tls, OtherCipherTest,
                         ::testing::Values("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"));

// 明文客户端：直接往端口上写 FWDS 帧，服务端当成失败的握手处理，不解析也不应答
TEST(Tls, PlaintextFrameIsNeverProcessed) {
  TlsServer fx;
  QTcpSocket plain;
  plain.connectToHost(QHostAddress::LocalHost, fx.port());
  ASSERT_TRUE(waitFor([&]() { return plain.state() == QAbstractSocket::ConnectedState; }));
  QByteArray frame;
  encodeFrame(static_cast<quint8>(MsgType::Login), 1, "{\"device_id\":\"DEV-001\"}", &frame);
  plain.write(frame);
  ASSERT_TRUE(waitFor([&]() { return fx.closeReasons.size() == 1; }));
  EXPECT_EQ(fx.closeReasons.first(), QStringLiteral("TLS 握手失败"));
  EXPECT_EQ(fx.reachedWaitLogin, 0);
  // 服务端回的只可能是 TLS 告警，不会是 FWDS 帧（帧以 "FW" 开头）
  waitFor([&]() { return plain.state() == QAbstractSocket::UnconnectedState; }, 1000);
  EXPECT_FALSE(plain.readAll().startsWith("FW"));
}
