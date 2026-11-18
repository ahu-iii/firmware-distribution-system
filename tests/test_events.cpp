// 事件闭环：设备 outbox 落盘与补传、服务端去重入库与对账（设计 4.6 节，协议 5.7 节）。
// 对应测试报告 UT-09（事件序号与去重）、FT-08（断网期间事件落盘）、FT-09（恢复后补传对账）、
// ST-09 的“重发已确认过的事件不重复入库”部分。
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/business/event_outbox.h"
#include "client/net/tcp_client.h"
#include "server/business/event_store.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using fwds_test::sharedPki;

namespace {

// ---------------- 设备端 outbox ----------------

// 记下 outbox 发出去的每一帧；online 为 false 时模拟“不在线，发不出去”。
struct FakeLink {
  bool online = true;
  QList<qint64> sentSeqs;
  QList<MsgType> sentTypes;
  EventOutbox::SendFn fn() {
    return [this](MsgType type, const QByteArray& body) {
      if (!online) return false;
      sentTypes.append(type);
      sentSeqs.append(QJsonDocument::fromJson(body).object().value(QStringLiteral("event_seq")).toInteger());
      return true;
    };
  }
};

QJsonObject progressFields(int percent) {
  QJsonObject f;
  f.insert(QStringLiteral("pkg_id"), QStringLiteral(""));
  f.insert(QStringLiteral("state"), QStringLiteral("DOWNLOADING"));
  f.insert(QStringLiteral("progress"), percent);
  return f;
}

QList<qint64> seqsOf(const EventOutbox& outbox) {
  QList<qint64> seqs;
  for (const EventOutbox::Event& e : outbox.pending()) seqs.append(e.seq);
  return seqs;
}

QList<qint64> range(qint64 from, qint64 to) {
  QList<qint64> r;
  for (qint64 i = from; i <= to; ++i) r.append(i);
  return r;
}

}  // namespace

// UT-09 前半：写 10 条后“重启”（重新打开同一个目录）再写 5 条，序号 1 ~ 15 连续，全部还在文件里
TEST(EventOutbox, SeqContinuesAcrossRestart) {
  QTemporaryDir dir;
  FakeLink link;
  {
    EventOutbox outbox(dir.path(), link.fn());
    QString error;
    ASSERT_TRUE(outbox.open(&error)) << error.toStdString();
    for (int i = 0; i < 10; ++i) EXPECT_EQ(outbox.record(MsgType::Progress, progressFields(i)), i + 1);
  }
  EventOutbox outbox(dir.path(), link.fn());
  QString error;
  ASSERT_TRUE(outbox.open(&error)) << error.toStdString();
  EXPECT_EQ(outbox.lastSeq(), 10);
  for (int i = 0; i < 5; ++i) outbox.record(MsgType::Progress, progressFields(i));
  EXPECT_EQ(seqsOf(outbox), range(1, 15));
  EXPECT_TRUE(link.sentSeqs.isEmpty());  // 从没登录过，一条都没发
}

// FT-08 / FT-09 的设备端：不在线时只落盘；登录后删掉已确认的，其余按序号补传；在线时新事件立即发送
TEST(EventOutbox, ResendsUnconfirmedAfterLoginInOrder) {
  QTemporaryDir dir;
  FakeLink link;
  EventOutbox outbox(dir.path(), link.fn());
  QString error;
  ASSERT_TRUE(outbox.open(&error));
  for (int i = 0; i < 4; ++i) outbox.record(MsgType::Progress, progressFields(i));
  EXPECT_TRUE(link.sentSeqs.isEmpty());

  outbox.onLoggedIn(1);  // 服务端说已经收到第 1 条
  EXPECT_EQ(link.sentSeqs, (QList<qint64>{2, 3, 4}));
  EXPECT_EQ(seqsOf(outbox), (QList<qint64>{2, 3, 4}));

  outbox.record(MsgType::Result, QJsonObject());
  EXPECT_EQ(link.sentSeqs.last(), 5);
  EXPECT_EQ(link.sentTypes.last(), MsgType::Result);

  // 心跳应答确认到 5：全部删除；断线后的新事件只落盘
  outbox.onAcked(5);
  EXPECT_EQ(outbox.pendingCount(), 0);
  outbox.onDisconnected();
  outbox.record(MsgType::Alert, QJsonObject());
  EXPECT_EQ(link.sentSeqs.size(), 4);
  EXPECT_EQ(outbox.pendingCount(), 1);
}

// 已确认的事件从文件里删掉；全部确认后重启，序号也不回退；event_base 报“确认到哪里”
TEST(EventOutbox, AckedEventsAreGoneAfterRestartAndSeqDoesNotGoBack) {
  QTemporaryDir dir;
  FakeLink link;
  {
    EventOutbox outbox(dir.path(), link.fn());
    QString error;
    ASSERT_TRUE(outbox.open(&error));
    for (int i = 0; i < 3; ++i) outbox.record(MsgType::Progress, progressFields(i));
    outbox.onLoggedIn(2);
    EXPECT_EQ(outbox.confirmedSeq(), 2);
  }
  {
    EventOutbox outbox(dir.path(), link.fn());
    QString error;
    ASSERT_TRUE(outbox.open(&error));
    EXPECT_EQ(seqsOf(outbox), (QList<qint64>{3}));
    EXPECT_EQ(outbox.confirmedSeq(), 2);
    outbox.onLoggedIn(3);
    EXPECT_EQ(outbox.pendingCount(), 0);
    EXPECT_EQ(outbox.confirmedSeq(), 3);
  }
  EventOutbox outbox(dir.path(), link.fn());
  QString error;
  ASSERT_TRUE(outbox.open(&error));
  EXPECT_EQ(outbox.pendingCount(), 0);
  EXPECT_EQ(outbox.record(MsgType::Progress, progressFields(0)), 4);
}

// 追加到一半断电：末尾留下半行。重新打开时丢掉它，文件重写干净，下一个事件沿用这个序号
TEST(EventOutbox, TornLastLineIsDroppedOnOpen) {
  QTemporaryDir dir;
  FakeLink link;
  {
    EventOutbox outbox(dir.path(), link.fn());
    QString error;
    ASSERT_TRUE(outbox.open(&error));
    outbox.record(MsgType::Progress, progressFields(1));
    outbox.record(MsgType::Progress, progressFields(2));
  }
  QFile events(QDir(dir.path()).filePath(QStringLiteral("events.jsonl")));
  ASSERT_TRUE(events.open(QIODevice::Append));
  events.write(R"({"type":48,"body":{"event_seq":3,"ts":17)");  // 没写完的一行
  events.close();

  EventOutbox outbox(dir.path(), link.fn());
  QString error;
  ASSERT_TRUE(outbox.open(&error));
  EXPECT_EQ(seqsOf(outbox), (QList<qint64>{1, 2}));
  EXPECT_EQ(outbox.record(MsgType::Progress, progressFields(3)), 3);

  EventOutbox reopened(dir.path(), link.fn());
  ASSERT_TRUE(reopened.open(&error));
  EXPECT_EQ(seqsOf(reopened), (QList<qint64>{1, 2, 3}));
}

// 设备数据目录被清空过：服务端确认的序号比本地分配过的还大，未确认事件接着服务端的序号重新编号
TEST(EventOutbox, RenumbersWhenServerIsAhead) {
  QTemporaryDir dir;
  FakeLink link;
  EventOutbox outbox(dir.path(), link.fn());
  QString error;
  ASSERT_TRUE(outbox.open(&error));
  outbox.record(MsgType::Progress, progressFields(1));
  outbox.record(MsgType::Progress, progressFields(2));

  outbox.onLoggedIn(57);
  EXPECT_EQ(link.sentSeqs, (QList<qint64>{58, 59}));
  EXPECT_EQ(outbox.lastSeq(), 59);
  EXPECT_EQ(outbox.record(MsgType::Progress, progressFields(3)), 60);
}

// ---------------- 服务端 EventStore ----------------

namespace {

QByteArray progressBody(qint64 seq, int percent = 10) {
  QJsonObject o = progressFields(percent);
  o.insert(QStringLiteral("event_seq"), seq);
  o.insert(QStringLiteral("ts"), 1793955601000.0);
  return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

QByteArray resultBody(qint64 seq, const QString& result, int code) {
  QJsonObject o;
  o.insert(QStringLiteral("event_seq"), seq);
  o.insert(QStringLiteral("ts"), 1793955601000.0);
  o.insert(QStringLiteral("pkg_id"), QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a11"));
  o.insert(QStringLiteral("release_id"), 12);
  o.insert(QStringLiteral("result"), result);
  o.insert(QStringLiteral("code"), code);
  o.insert(QStringLiteral("fw_version"), QStringLiteral("2.1.0"));
  return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

// 后台 + 已注册的 DEV-001 + EventStore；记下 EventStore 交给业务的事件序号
struct StoreFixture {
  explicit StoreFixture(const QString& dbPath = QStringLiteral(":memory:")) : backend(dbPath) {
    DeviceRecord d;
    if (!backend.registry.find(kDev, &d)) backend.registerDevice(sharedPki().dev001);
    QObject::connect(&store, &EventStore::progressStored,
                     [this](const QString&, const QString&, const QString&, int progress) {
                       released.append(progress);
                     });
  }
  qint64 ack() const { return store.eventAck(kDev); }

  const QString kDev = QStringLiteral("DEV-001");
  fwds_test::ServerBackend backend;
  EventStore store{&backend.db, &backend.registry};
  QList<int> released;  // progressBody 里把序号当进度填，这里就是交给业务的序号
};

}  // namespace

// UT-09 后半：重复收到第 3 条不入库；乱序收到第 7、6 条，确认序号只在补齐后推进；业务按序号收到
TEST(EventStore, DeduplicatesAndAdvancesAckOnlyWhenContiguous) {
  StoreFixture fx;
  for (int seq = 1; seq <= 5; ++seq) {
    EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(seq, seq)),
              EventStore::Outcome::Stored);
  }
  EXPECT_EQ(fx.ack(), 5);
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(3, 3)),
            EventStore::Outcome::Duplicate);

  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(7, 7)),
            EventStore::Outcome::Stored);
  EXPECT_EQ(fx.ack(), 5);  // 缺第 6 条，第 7 条只暂存
  EXPECT_EQ(fx.store.heldCount(fx.kDev), 1);
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(7, 7)),
            EventStore::Outcome::Duplicate);  // 暂存着的也不重复入库

  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(6, 6)),
            EventStore::Outcome::Stored);
  EXPECT_EQ(fx.ack(), 7);
  EXPECT_EQ(fx.store.heldCount(fx.kDev), 0);
  EXPECT_EQ(fx.released, (QList<int>{1, 2, 3, 4, 5, 6, 7}));
  EXPECT_EQ(fx.store.recentEvents(fx.kDev, 100).size(), 7);
}

// 格式不对的事件回 1005（由会话发送），不入库、不推进确认序号
TEST(EventStore, RejectsMalformedEvents) {
  StoreFixture fx;
  const QList<QByteArray> bad = {
      "not json",
      R"({"ts":1,"pkg_id":"","state":"IDLE","progress":0})",                 // 没有 event_seq
      R"({"event_seq":0,"ts":1,"pkg_id":"","state":"IDLE","progress":0})",   // 序号从 1 开始
      R"({"event_seq":1.5,"ts":1,"pkg_id":"","state":"IDLE","progress":0})", // 不是整数
      R"({"event_seq":1,"ts":1,"pkg_id":"","state":"IDLE","progress":101})", // 进度超过 100
      R"({"event_seq":1,"ts":1,"pkg_id":""})",                                // 缺 state
  };
  for (const QByteArray& body : bad) {
    EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, body), EventStore::Outcome::Malformed)
        << body.toStdString();
  }
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Result, resultBody(1, QStringLiteral("OK"), 0)),
            EventStore::Outcome::Malformed);
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, QByteArray(kMaxEventBody + 1, ' ')),
            EventStore::Outcome::Malformed);
  EXPECT_EQ(fx.ack(), 0);
  EXPECT_TRUE(fx.store.recentEvents(fx.kDev, 10).isEmpty());
}

// 序号超前太多的不入库，防止用很大的序号把事件表撑满
TEST(EventStore, DropsEventsTooFarAhead) {
  StoreFixture fx;
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(kMaxEventGap + 1)),
            EventStore::Outcome::OutOfWindow);
  EXPECT_EQ(fx.store.accept(fx.kDev, MsgType::Progress, progressBody(kMaxEventGap)),
            EventStore::Outcome::Stored);
  EXPECT_EQ(fx.store.heldCount(fx.kDev), 1);
}

// RESULT 交给发布模块的参数；失败和回滚把设备行标红
TEST(EventStore, ResultIsHandedOverWithReleaseAndPackage) {
  StoreFixture fx;
  QStringList results;
  qint64 releaseId = -1;
  QString pkgId;
  int code = -1;
  QObject::connect(&fx.store, &EventStore::resultStored,
                   [&](const QString& device, qint64 release, const QString& pkg,
                       const QString& result, int c, const QString&) {
                     EXPECT_EQ(device, QStringLiteral("DEV-001"));
                     releaseId = release;
                     pkgId = pkg;
                     code = c;
                     results.append(result);
                   });
  fx.store.accept(fx.kDev, MsgType::Result, resultBody(1, QStringLiteral("ROLLED_BACK"), 3007));
  EXPECT_EQ(results, QStringList{QStringLiteral("ROLLED_BACK")});
  EXPECT_EQ(releaseId, 12);
  EXPECT_EQ(pkgId, QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a11"));
  EXPECT_EQ(code, 3007);
  DeviceRecord d;
  ASSERT_TRUE(fx.backend.registry.find(fx.kDev, &d));
  EXPECT_FALSE(d.alert.isEmpty());
}

// 确认序号和暂存的事件都在数据库里：服务端重启后接着对账
TEST(EventStore, AckAndHeldEventsSurviveRestart) {
  QTemporaryDir dir;
  const QString dbPath = QDir(dir.path()).filePath(QStringLiteral("server.db"));
  {
    StoreFixture fx(dbPath);
    fx.store.accept(fx.kDev, MsgType::Progress, progressBody(1, 1));
    fx.store.accept(fx.kDev, MsgType::Progress, progressBody(3, 3));
    EXPECT_EQ(fx.ack(), 1);
  }
  StoreFixture fx(dbPath);
  EXPECT_EQ(fx.ack(), 1);
  EXPECT_EQ(fx.store.heldCount(fx.kDev), 1);
  fx.store.accept(fx.kDev, MsgType::Progress, progressBody(2, 2));
  EXPECT_EQ(fx.ack(), 3);
  EXPECT_EQ(fx.released, (QList<int>{2, 3}));
}

// 对账：服务端数据库回滚到旧备份，只确认到 3；设备说它早已确认删除到 10。
// 4 ~ 10 两边都没有了：告警说明缺口，确认序号直接推到 10；暂存着的 8 和紧接着的 11 一并处理
TEST(EventStore, ReconcileSkipsEventsTheDeviceNoLongerHas) {
  StoreFixture fx;
  for (int seq = 1; seq <= 3; ++seq) fx.store.accept(fx.kDev, MsgType::Progress, progressBody(seq, seq));
  fx.store.accept(fx.kDev, MsgType::Progress, progressBody(8, 8));
  fx.store.accept(fx.kDev, MsgType::Progress, progressBody(11, 11));
  fx.store.accept(fx.kDev, MsgType::Progress, progressBody(13, 13));
  EXPECT_EQ(fx.ack(), 3);

  EXPECT_EQ(fx.store.reconcileOnLogin(fx.kDev, 2), 3);  // 设备落后于服务端：正常，不动
  EXPECT_EQ(fx.store.reconcileOnLogin(fx.kDev, 10), 11);
  EXPECT_EQ(fx.ack(), 11);
  EXPECT_EQ(fx.store.heldCount(fx.kDev), 1);  // 13 还在等 12
  EXPECT_EQ(fx.released, (QList<int>{1, 2, 3, 8, 11}));
  DeviceRecord d;
  ASSERT_TRUE(fx.backend.registry.find(fx.kDev, &d));
  EXPECT_TRUE(d.alert.contains(QStringLiteral("4 ~ 10")));
}

// ---------------- 联调：真实 TLS 连接上的补传与对账（FT-08、FT-09）----------------

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 300;
  p.reconnectBackoffMs = {30, 30};
  return p;
}

// 服务端：网络层 + 登录裁决 + 事件入库，与 server/main.cpp 的接法相同
struct EventServer {
  EventServer() {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.protocol = fastParams();
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol, &backend.registry, &backend.throttle);
    monitor = std::make_unique<HeartbeatMonitor>(server.get(), &backend.registry);
    events = std::make_unique<EventStore>(&backend.db, &backend.registry, server.get());
    login->setEventStore(events.get());
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
    });
    EXPECT_TRUE(server->start());
    backend.registerDevice(sharedPki().dev001);
  }

  fwds_test::ServerBackend backend;
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  std::unique_ptr<HeartbeatMonitor> monitor;
  std::unique_ptr<EventStore> events;
};

// 设备：TcpClient + 数据目录里的 outbox，与 client/main.cpp 的接法相同。
// 每构造一次相当于设备进程重新启动一次（outbox 从磁盘读回）
struct EventDevice {
  EventDevice(quint16 port, const QString& outboxDir)
      : security(sharedPki().pki.security(sharedPki().dev001)) {
    ClientConfig c;
    c.serverHost = QStringLiteral("127.0.0.1");
    c.serverPort = port;
    c.deviceId = QStringLiteral("DEV-001");
    c.model = QStringLiteral("PLC-X200");
    c.protocol = fastParams();
    client = std::make_unique<TcpClient>(c, security.get());
    outbox = std::make_unique<EventOutbox>(outboxDir, [this](MsgType type, const QByteArray& body) {
      return client->send(type, body);
    });
    QString error;
    EXPECT_TRUE(outbox->open(&error)) << error.toStdString();
    client->setLoginProvider([this]() {
      QJsonObject o;
      o.insert(QStringLiteral("device_id"), QStringLiteral("DEV-001"));
      o.insert(QStringLiteral("model"), QStringLiteral("PLC-X200"));
      o.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
      o.insert(QStringLiteral("event_base"), outbox->confirmedSeq());
      return o;
    });
    QObject::connect(client.get(), &TcpClient::loggedIn, [this](const QJsonObject& r) {
      outbox->onLoggedIn(r.value(QStringLiteral("event_ack")).toInteger());
    });
    QObject::connect(client.get(), &TcpClient::heartbeatAcked, [this](const QJsonObject& a) {
      outbox->onAcked(a.value(QStringLiteral("event_ack")).toInteger(-1));
    });
    QObject::connect(client.get(), &TcpClient::stateChanged, [this](TcpClient::State s) {
      if (s != TcpClient::State::Online) outbox->onDisconnected();
    });
  }

  std::unique_ptr<TlsChannelSecurity> security;
  std::unique_ptr<TcpClient> client;
  std::unique_ptr<EventOutbox> outbox;
};

}  // namespace

// FT-08 + FT-09：离线期间产生的事件落盘；进程重启后还在；上线后按序号补传，
// 服务端序号 1 ~ 5 连续、无重复，设备 outbox 清空
TEST(EventSync, OfflineEventsAreUploadedInOrderAfterReconnect) {
  EventServer fx;
  QTemporaryDir dir;
  const QString kDev = QStringLiteral("DEV-001");

  {
    EventDevice dev(fx.server->serverPort(), dir.path());
    for (int i = 1; i <= 3; ++i) dev.outbox->record(MsgType::Progress, progressFields(i));
    dev.client->start();
    ASSERT_TRUE(waitFor([&]() { return fx.events->eventAck(kDev) == 3; }));
    ASSERT_TRUE(waitFor([&]() { return dev.outbox->pendingCount() == 0; }));
    dev.client->stop();
    // 断网期间又产生两条，然后进程被结束
    dev.outbox->record(MsgType::Progress, progressFields(4));
    dev.outbox->record(MsgType::Result, QJsonDocument::fromJson(resultBody(0, QStringLiteral("SUCCESS"), 0)).object());
    EXPECT_EQ(dev.outbox->pendingCount(), 2);
  }

  EventDevice dev(fx.server->serverPort(), dir.path());  // 重启：未确认事件从文件读回
  EXPECT_EQ(seqsOf(*dev.outbox), (QList<qint64>{4, 5}));
  dev.client->start();
  ASSERT_TRUE(waitFor([&]() { return fx.events->eventAck(kDev) == 5; }));
  ASSERT_TRUE(waitFor([&]() { return dev.outbox->pendingCount() == 0; }));

  QList<qint64> stored;
  for (const StoredEvent& e : fx.events->recentEvents(kDev, 100)) stored.prepend(e.seq);
  EXPECT_EQ(stored, range(1, 5));
  EXPECT_EQ(fx.events->heldCount(kDev), 0);
  dev.client->stop();
}
