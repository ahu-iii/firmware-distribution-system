// 网络层联调测试：在本机回环上起真实的 TcpServer / TcpClient，走真实的 TLS 1.3 双向认证
// （证书由 tests/test_pki.h 在内存里现签），覆盖登录、心跳、序号检查、非法帧、各类超时和断线重连。
// 端口用 0 让系统分配，超时参数缩短到几百毫秒以内。
#include <QJsonDocument>
#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <tuple>
#include <gtest/gtest.h>

#include "client/net/tcp_client.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "server/business/heartbeat_monitor.h"
#include "tests/test_pki.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using fwds_test::sharedPki;

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 400;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 300;
  p.reconnectBackoffMs = {50, 100, 200};
  return p;
}

QByteArray loginBody(qint64 ts = QDateTime::currentMSecsSinceEpoch()) {
  QJsonObject o;
  o.insert(QStringLiteral("device_id"), QStringLiteral("DEV-001"));
  o.insert(QStringLiteral("ts"), ts);
  return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

QByteArray wire(MsgType type, quint64 seq, const QByteArray& body) {
  QByteArray out;
  encodeFrame(static_cast<quint8>(type), seq, body, &out);
  return out;
}

// 合法的心跳消息体（协议 5.3 节）。格式不对的心跳服务端回 1005 并丢弃
const QByteArray kHeartbeatBody = R"({"state":"IDLE","progress":0,"uptime":1})";

int errorCodeOf(const Frame& frame) {
  return QJsonDocument::fromJson(frame.body).object().value(QStringLiteral("code")).toInt();
}

// 服务端 + 登录处理，监听回环地址的随机端口。
struct ServerFixture {
  explicit ServerFixture(ProtocolParams params = fastParams(), int maxPerIp = 50) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.maxConnectionsPerIp = maxPerIp;
    config.protocol = params;
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(params, &backend.registry, &backend.throttle);
    backend.registerDevice(sharedPki().dev001);
    backend.registerDevice(sharedPki().dev002);
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      ++opened;
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
      QObject::connect(s, &Session::heartbeatReceived, [this]() { ++heartbeats; });
    });
    QObject::connect(server.get(), &TcpServer::sessionClosed,
                     [this](Session*, const QString& reason) {
                       ++closed;
                       lastCloseReason = reason;
                     });
    EXPECT_TRUE(server->start());
  }
  quint16 port() const { return server->serverPort(); }
  int onlineCount() const {
    int n = 0;
    for (Session* s : server->sessions()) n += s->state() == Session::State::Online;
    return n;
  }

  fwds_test::ServerBackend backend;
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  int opened = 0;
  int closed = 0;
  int heartbeats = 0;
  QString lastCloseReason;
};

// 手工拼帧的“原始客户端”，用来发协议实现不会发的非法数据。
// 用 DEV-001 的证书完成 TLS 握手，之后在加密信道里写任意字节。
struct RawPeer {
  explicit RawPeer(quint16 port) {
    // 用信号记录“连上过”：被服务端立刻断开时，状态可能在一次事件处理里就回到未连接
    QObject::connect(&socket, &QAbstractSocket::connected, [this]() { everConnected = true; });
    security->prepare(&socket, false);
    socket.connectToHostEncrypted(QStringLiteral("127.0.0.1"), port);
    EXPECT_TRUE(waitFor([this]() { return everConnected; }));
  }
  void write(const QByteArray& data) { socket.write(data); }
  // 等到连接被对端关闭，返回期间收到的所有帧。
  QList<Frame> readUntilClosed(int timeoutMs = 3000) {
    closedByPeer =
        waitFor([this]() { return socket.state() == QAbstractSocket::UnconnectedState; }, timeoutMs);
    return drain();
  }
  QList<Frame> drain() {
    decoder.feed(socket.readAll());
    QList<Frame> frames;
    Frame f;
    while (decoder.next(&f) == DecodeStatus::FrameReady) frames.append(f);
    return frames;
  }
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().dev001);
  QSslSocket socket;
  FrameDecoder decoder;
  bool everConnected = false;
  bool closedByPeer = false;
};

// 能完成 TLS 握手、但之后不按协议应答的服务端，用来测客户端的超时处理。
class MuteTlsServer : public QTcpServer {
 public:
  std::function<void(QSslSocket*)> onEncrypted;

 protected:
  void incomingConnection(qintptr descriptor) override {
    auto* socket = new QSslSocket(this);
    socket->setSocketDescriptor(descriptor);
    security_->prepare(socket, true);
    connect(socket, &QSslSocket::encrypted, this, [this, socket]() {
      if (onEncrypted) onEncrypted(socket);
    });
    socket->startServerEncryption();
  }

 private:
  std::unique_ptr<TlsChannelSecurity> security_ = sharedPki().pki.security(sharedPki().server);
};

ClientConfig clientConfig(quint16 port, ProtocolParams params = fastParams()) {
  ClientConfig c;
  c.serverHost = QStringLiteral("127.0.0.1");
  c.serverPort = port;
  c.deviceId = QStringLiteral("DEV-001");
  c.model = QStringLiteral("PLC-X200");
  c.protocol = params;
  return c;
}

void useValidLogin(TcpClient& client) {
  client.setLoginProvider([]() { return QJsonDocument::fromJson(loginBody()).object(); });
}

}  // namespace

// ---------- 正常流程 ----------

TEST(Network, LoginThenHeartbeatsAreAcked) {
  ServerFixture fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fx.port()), security.get());
  useValidLogin(client);
  int acks = 0;
  QJsonObject loginResult;
  QObject::connect(&client, &TcpClient::heartbeatAcked, [&](const QJsonObject& ack) {
    ++acks;
    EXPECT_TRUE(ack.contains(QStringLiteral("server_time")));
    EXPECT_TRUE(ack.contains(QStringLiteral("event_ack")));
  });
  QObject::connect(&client, &TcpClient::loggedIn, [&](const QJsonObject& r) { loginResult = r; });

  client.start();
  ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));
  EXPECT_EQ(loginResult.value(QStringLiteral("result")).toString(), QStringLiteral("OK"));
  EXPECT_EQ(loginResult.value(QStringLiteral("session_id")).toString().size(), 32);
  ASSERT_TRUE(waitFor([&]() { return acks >= 3; }));
  EXPECT_GE(fx.heartbeats, 3);
  EXPECT_EQ(fx.onlineCount(), 1);
  EXPECT_EQ(fx.server->sessions().first()->deviceId(), QStringLiteral("DEV-001"));

  // 心跳持续期间连接保持在线（超过离线判定时间也不掉线）
  spin(2 * fastParams().heartbeatTimeoutMs);
  EXPECT_EQ(client.state(), TcpClient::State::Online);
  EXPECT_EQ(fx.closed, 0);

  client.stop();
  ASSERT_TRUE(waitFor([&]() { return fx.closed == 1; }));
  EXPECT_EQ(fx.lastCloseReason, QStringLiteral("设备正常关闭"));  // 收到了 BYE
}

// 粘包 + 半包走真实 socket：LOGIN 和两个 HEARTBEAT 拼在一起，分两段发出
TEST(Network, StickyAndSplitFramesOverSocket) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  const QByteArray stream = wire(MsgType::Login, 1, loginBody()) +
                            wire(MsgType::Heartbeat, 2, kHeartbeatBody) + wire(MsgType::Heartbeat, 3, kHeartbeatBody);
  peer.write(stream.left(20));
  spin(50);
  peer.write(stream.mid(20));
  ASSERT_TRUE(waitFor([&]() { return fx.heartbeats == 2; }));
  QList<Frame> frames;
  ASSERT_TRUE(waitFor([&]() { frames += peer.drain(); return frames.size() == 3; }));
  EXPECT_EQ(frames[0].type, static_cast<quint8>(MsgType::LoginResult));
  EXPECT_EQ(frames[1].type, static_cast<quint8>(MsgType::HeartbeatAck));
  // 服务端发出的帧序号也从 1 连续递增
  EXPECT_EQ(frames[0].seq, 1u);
  EXPECT_EQ(frames[1].seq, 2u);
  EXPECT_EQ(frames[2].seq, 3u);
}

// ---------- 非法帧 ----------

struct BadHeaderCase {
  const char* name;
  QByteArray bytes;
  int expectedCode;
};

class BadHeaderTest : public ::testing::TestWithParam<BadHeaderCase> {};

TEST_P(BadHeaderTest, ServerSendsErrorAndDisconnects) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(GetParam().bytes);
  const QList<Frame> frames = peer.readUntilClosed();
  EXPECT_TRUE(peer.closedByPeer);
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(frames[0].type, static_cast<quint8>(MsgType::Error));
  EXPECT_EQ(errorCodeOf(frames[0]), GetParam().expectedCode);
  EXPECT_TRUE(waitFor([&]() { return fx.closed == 1; }));
}

INSTANTIATE_TEST_SUITE_P(
    Network, BadHeaderTest,
    ::testing::Values(
        BadHeaderCase{"BadMagic", QByteArray::fromHex("58580201000000000000000100000000"), 1001},
        BadHeaderCase{"BadVersion", QByteArray::fromHex("46570101000000000000000100000000"), 1002},
        // 只发帧头，Length = 1 MB + 1：不等 Body 就应拒绝
        BadHeaderCase{"FrameTooLarge", QByteArray::fromHex("46570201000000000000000100100001"), 1003}),
    [](const ::testing::TestParamInfo<BadHeaderCase>& info) { return std::string(info.param.name); });

TEST(Network, FirstFrameMustHaveSeqOne) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 2, loginBody()));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(errorCodeOf(frames[0]), 1007);
}

// 重放：登录后把已经发过的 HEARTBEAT（Seq=2）原样再发一次
TEST(Network, ReplayedFrameIsRejectedWithSeqError) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  const QByteArray heartbeat = wire(MsgType::Heartbeat, 2, kHeartbeatBody);
  peer.write(wire(MsgType::Login, 1, loginBody()));
  peer.write(heartbeat);
  ASSERT_TRUE(waitFor([&]() { return fx.heartbeats == 1; }));
  peer.write(heartbeat);
  const QList<Frame> frames = peer.readUntilClosed();
  EXPECT_TRUE(peer.closedByPeer);
  ASSERT_EQ(frames.size(), 3);  // LOGIN_RESULT、HEARTBEAT_ACK、ERROR
  EXPECT_EQ(frames[2].type, static_cast<quint8>(MsgType::Error));
  EXPECT_EQ(errorCodeOf(frames[2]), 1007);
  EXPECT_EQ(fx.heartbeats, 1);  // 重放的那一帧没有被处理
}

// 跳号（丢帧或插入）同样拒绝
TEST(Network, SkippedSeqIsRejected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody()));
  peer.write(wire(MsgType::Heartbeat, 3, kHeartbeatBody));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 2);
  EXPECT_EQ(errorCodeOf(frames[1]), 1007);
  EXPECT_EQ(fx.heartbeats, 0);
}

// ET-01：登录之后再发 Magic 错误、版本为 9 的帧，同样回 ERROR 并断开
TEST(Network, BadHeaderAfterLoginClosesConnection) {
  for (const auto& [name, patch, code] :
       {std::make_tuple("BadMagic", 0, 1001), std::make_tuple("BadVersion", 2, 1002)}) {
    SCOPED_TRACE(name);
    ServerFixture fx;
    RawPeer peer(fx.port());
    peer.write(wire(MsgType::Login, 1, loginBody()));
    ASSERT_TRUE(waitFor([&]() { return fx.onlineCount() == 1; }));
    QByteArray bad = wire(MsgType::Heartbeat, 2, kHeartbeatBody);
    if (patch == 0) bad[0] = 'X';
    else bad[2] = 9;
    peer.write(bad);
    const QList<Frame> frames = peer.readUntilClosed();
    EXPECT_TRUE(peer.closedByPeer);
    ASSERT_EQ(frames.size(), 2);  // LOGIN_RESULT、ERROR
    EXPECT_EQ(errorCodeOf(frames[1]), code);
  }
}

// ET-02：心跳消息体不是 JSON、缺字段或类型不对，回 1005、不算心跳，连接不断开（协议 5.3 节）。
// 回归 BUG-007：原来格式不对的心跳照常应答
TEST(Network, MalformedHeartbeatGetsBadJsonAndIsNotCounted) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody()));
  ASSERT_TRUE(waitFor([&]() { return fx.onlineCount() == 1; }));
  const QList<QByteArray> bad = {
      "{\"state\":\"IDLE\",",                                  // 不完整的 JSON
      "[1,2,3]",                                                // 不是对象
      "{}",                                                     // 缺字段
      R"({"state":12345,"progress":"many","uptime":null})",    // 类型不对
      R"({"state":"IDLE","progress":101,"uptime":1})",         // 进度超范围
      R"({"state":"IDLE","progress":0.5,"uptime":1})",         // 不是整数
  };
  quint64 seq = 2;
  for (const QByteArray& body : bad) peer.write(wire(MsgType::Heartbeat, seq++, body));
  peer.write(wire(MsgType::Heartbeat, seq++, kHeartbeatBody));  // 最后一个是合法的
  QList<Frame> frames;
  ASSERT_TRUE(waitFor([&]() {
    frames += peer.drain();
    return frames.size() == 1 + bad.size() + 1;
  }));
  for (int i = 1; i <= bad.size(); ++i) {
    EXPECT_EQ(frames[i].type, static_cast<quint8>(MsgType::Error));
    EXPECT_EQ(errorCodeOf(frames[i]), 1005);
  }
  EXPECT_EQ(frames.last().type, static_cast<quint8>(MsgType::HeartbeatAck));
  EXPECT_EQ(fx.heartbeats, 1);  // 只有合法的那一个算心跳
  EXPECT_EQ(fx.onlineCount(), 1);
}

// ---------- 连接状态机 ----------

TEST(Network, MessageBeforeLoginIsUnexpected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Heartbeat, 1, kHeartbeatBody));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(errorCodeOf(frames[0]), 1004);
  EXPECT_EQ(fx.heartbeats, 0);
}

TEST(Network, ServerOnlyMessageFromDeviceIsUnexpected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody()));
  peer.write(wire(MsgType::UpdateNotify, 2, "{}"));  // 只有服务端能发
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 2);
  EXPECT_EQ(errorCodeOf(frames[1]), 1004);
}

TEST(Network, UnknownMessageTypeIsUnexpected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody()));
  peer.write(wire(static_cast<MsgType>(0x55), 2, "{}"));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 2);
  EXPECT_EQ(errorCodeOf(frames[1]), 1004);
}

TEST(Network, LoginTimeoutClosesSilentConnection) {
  ServerFixture fx;
  RawPeer peer(fx.port());  // 连上之后什么都不发
  const QList<Frame> frames = peer.readUntilClosed();
  EXPECT_TRUE(peer.closedByPeer);
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(errorCodeOf(frames[0]), 2001);
}

TEST(Network, LoginWithStaleTimestampIsRejected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody(QDateTime::currentMSecsSinceEpoch() - 120000)));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(frames[0].type, static_cast<quint8>(MsgType::LoginResult));
  const QJsonObject result = QJsonDocument::fromJson(frames[0].body).object();
  EXPECT_EQ(result.value(QStringLiteral("result")).toString(), QStringLiteral("FAIL"));
  EXPECT_EQ(result.value(QStringLiteral("code")).toInt(), 2002);
  EXPECT_EQ(fx.onlineCount(), 0);
}

TEST(Network, MalformedLoginIsRejected) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, "not json"));
  const QList<Frame> frames = peer.readUntilClosed();
  ASSERT_EQ(frames.size(), 1);
  EXPECT_EQ(QJsonDocument::fromJson(frames[0].body).object().value(QStringLiteral("code")).toInt(),
            1005);
}

// 登录后不再发心跳：服务端在离线判定时间后断开
TEST(Network, ServerDropsSessionWithoutHeartbeat) {
  ServerFixture fx;
  RawPeer peer(fx.port());
  peer.write(wire(MsgType::Login, 1, loginBody()));
  ASSERT_TRUE(waitFor([&]() { return fx.onlineCount() == 1; }));
  peer.readUntilClosed();
  EXPECT_TRUE(peer.closedByPeer);
  EXPECT_EQ(fx.lastCloseReason, QStringLiteral("心跳超时"));
}

TEST(Network, PerIpConnectionLimit) {
  ServerFixture fx(fastParams(), 2);
  RawPeer a(fx.port());
  RawPeer b(fx.port());
  ASSERT_TRUE(waitFor([&]() { return fx.opened == 2; }));
  RawPeer c(fx.port());  // 第 3 条：TCP 能连上，但服务端立刻断开，不建 Session
  c.readUntilClosed(1000);
  EXPECT_TRUE(c.closedByPeer);
  EXPECT_EQ(fx.opened, 2);
  EXPECT_EQ(a.socket.state(), QAbstractSocket::ConnectedState);
}

// ---------- 客户端：重连与超时 ----------

// 服务端没起来：按退避序列重试，起来之后自动连上
TEST(Network, ClientRetriesWithBackoffUntilServerAppears) {
  // 先占一个端口再释放，得到一个当前没人监听的端口
  quint16 port = 0;
  {
    QTcpServer probe;
    ASSERT_TRUE(probe.listen(QHostAddress::LocalHost, 0));
    port = probe.serverPort();
  }
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(port), security.get());
  useValidLogin(client);
  QList<int> delays;
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int delayMs, const QString&) { delays.append(delayMs); });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return delays.size() >= 4; }));
  EXPECT_EQ(delays.mid(0, 4), (QList<int>{50, 100, 200, 200}));  // 递增后封顶

  ServerFixture fx;
  fx.server->close();
  fx.config.listenPort = port;
  fx.server = std::make_unique<TcpServer>(fx.config, fx.security.get());
  QObject::connect(fx.server.get(), &TcpServer::sessionOpened, [&fx](Session* s) {
    QObject::connect(s, &Session::loginRequested, fx.login.get(), &LoginHandler::handle);
  });
  ASSERT_TRUE(fx.server->start());
  ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));
}

// 在线时被服务端踢掉：重连、重新登录，退避从头开始
TEST(Network, ClientReconnectsAfterServerDropsConnection) {
  ServerFixture fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fx.port()), security.get());
  useValidLogin(client);
  QList<int> delays;
  int logins = 0;
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int delayMs, const QString&) { delays.append(delayMs); });
  QObject::connect(&client, &TcpClient::loggedIn, [&]() { ++logins; });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return logins == 1; }));

  for (int round = 2; round <= 3; ++round) {
    ASSERT_EQ(fx.server->sessions().size(), 1);
    fx.server->sessions().first()->close(QStringLiteral("测试踢线"));
    ASSERT_TRUE(waitFor([&]() { return logins == round; }));
  }
  // 每次登录成功都会重置退避，所以两次断线都只等第一个值
  EXPECT_EQ(delays, (QList<int>{50, 50}));
  // 新连接的心跳能正常被接受，说明两个方向的序号都从 1 重新开始
  const int before = fx.heartbeats;
  ASSERT_TRUE(waitFor([&]() { return fx.heartbeats >= before + 2; }));
  EXPECT_EQ(client.state(), TcpClient::State::Online);
}

// 服务端登录后不再应答心跳（模拟半开连接）：客户端超时后主动断开重连
TEST(Network, ClientDropsConnectionWhenAcksStop) {
  MuteTlsServer mute;
  ASSERT_TRUE(mute.listen(QHostAddress::LocalHost, 0));
  int connections = 0;
  mute.onEncrypted = [&](QSslSocket* s) {
    ++connections;
    // 只回 LOGIN_RESULT(OK)，之后保持沉默
    QJsonObject ok;
    ok.insert(QStringLiteral("result"), QStringLiteral("OK"));
    s->write(wire(MsgType::LoginResult, 1, QJsonDocument(ok).toJson(QJsonDocument::Compact)));
  };
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(mute.serverPort()), security.get());
  useValidLogin(client);
  QStringList reasons;
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int, const QString& reason) { reasons.append(reason); });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));
  ASSERT_TRUE(waitFor([&]() { return !reasons.isEmpty(); }));
  EXPECT_EQ(reasons.first(), QStringLiteral("心跳应答超时"));
  ASSERT_TRUE(waitFor([&]() { return connections >= 2; }));  // 已经发起了重连
}

// 服务端接受 TCP 但既不握手也不回 LOGIN_RESULT：客户端在登录时限后放弃这条连接
TEST(Network, ClientGivesUpWhenLoginResultNeverArrives) {
  QTcpServer mute;
  ASSERT_TRUE(mute.listen(QHostAddress::LocalHost, 0));
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(mute.serverPort()), security.get());
  useValidLogin(client);
  QStringList reasons;
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int, const QString& reason) { reasons.append(reason); });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return !reasons.isEmpty(); }));
  EXPECT_EQ(reasons.first(), QStringLiteral("连接或登录超时"));
}

// 登录被拒：通知上层错误码，然后继续按退避重试（不重置退避）
TEST(Network, ClientReportsLoginFailureAndKeepsBackingOff) {
  ServerFixture fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fx.port()), security.get());
  client.setLoginProvider([]() {
    return QJsonDocument::fromJson(loginBody(QDateTime::currentMSecsSinceEpoch() - 120000)).object();
  });
  QList<int> codes;
  QList<int> delays;
  QObject::connect(&client, &TcpClient::loginFailed, [&](int code) { codes.append(code); });
  QObject::connect(&client, &TcpClient::reconnectScheduled,
                   [&](int delayMs, const QString&) { delays.append(delayMs); });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return codes.size() >= 3; }));
  EXPECT_EQ(codes.first(), 2002);
  EXPECT_EQ(delays.mid(0, 3), (QList<int>{50, 100, 200}));
  EXPECT_NE(client.state(), TcpClient::State::Online);
}

// 服务端向在线设备发业务帧，客户端原样交给上层
TEST(Network, BusinessFramesPassThroughBothWays) {
  ServerFixture fx;
  const auto security = sharedPki().pki.security(sharedPki().dev001);
  TcpClient client(clientConfig(fx.port()), security.get());
  useValidLogin(client);
  QList<Frame> atClient;
  QList<Frame> atServer;
  QObject::connect(&client, &TcpClient::frameReceived, [&](const Frame& f) { atClient.append(f); });
  QObject::connect(fx.server.get(), &TcpServer::sessionOpened, [&](Session* s) {
    QObject::connect(s, &Session::frameReceived,
                     [&](Session*, const Frame& f) { atServer.append(f); });
  });
  client.start();
  ASSERT_TRUE(waitFor([&]() { return client.state() == TcpClient::State::Online; }));

  const QByteArray chunk(70000, '\x5a');  // 比一次 socket 读取大，必然分多次到达
  ASSERT_TRUE(fx.server->sessions().first()->send(MsgType::ChunkData, chunk));
  ASSERT_TRUE(client.send(MsgType::ChunkReq, "{\"from_index\":0}"));
  ASSERT_TRUE(waitFor([&]() { return atClient.size() == 1 && atServer.size() == 1; }));
  EXPECT_EQ(atClient[0].type, static_cast<quint8>(MsgType::ChunkData));
  EXPECT_EQ(atClient[0].body, chunk);
  EXPECT_EQ(atServer[0].type, static_cast<quint8>(MsgType::ChunkReq));
}
