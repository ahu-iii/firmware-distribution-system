// 分片下载与断点续传的联调：真实 TLS、真实 TcpServer / TcpClient，
// 服务端 FirmwareRepo + ChunkService，设备端 Downloader + ResumeStore。
// 对应测试报告 FT-05（分片正确性）、FT-06（断点续传）、ST-11（越权与越界请求）。
// 服务端和设备在同一个线程的同一个事件循环里跑：只要有一处阻塞等待，这些用例就会卡死超时。
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTimer>
#include <gtest/gtest.h>

#include "client/business/downloader.h"
#include "client/net/tcp_client.h"
#include "common/update_messages.h"
#include "server/business/chunk_service.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "tests/test_fsk.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 300;
  p.reconnectBackoffMs = {30, 30};
  p.chunkWindow = 4;
  p.chunkWindowTimeoutMs = 300;
  return p;
}

class AllowAll : public AntiRollback {
 public:
  bool allows(const Manifest&, QString*) const override { return true; }
};

// 用签发工具的同一个函数在临时目录里做一个 .fwpkg。
struct PackageFile {
  PackageFile(const QTemporaryDir& dir, const QString& name, int imageSize)
      : image(randomBytes(imageSize)), path(dir.filePath(name + QStringLiteral(".fwpkg"))) {
    const QString imagePath = dir.filePath(name + QStringLiteral(".bin"));
    QFile file(imagePath);
    EXPECT_TRUE(file.open(QIODevice::WriteOnly));
    file.write(image);
    file.close();
    QString error;
    EXPECT_TRUE(signFirmware(imagePath, sampleInfo(), sharedFsk().key.get(), path, &manifest, &error))
        << error.toStdString();
  }
  QByteArray image;
  QString path;
  Manifest manifest;
};

// 服务端：网络层 + 登录 + 在线状态 + 固件仓库 + 分片服务。port 为 0 时由系统分配。
struct Server {
  explicit Server(fwds_test::ServerBackend* backend, quint16 port = 0) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = port;
    config.maxConnectionsPerIp = 50;
    config.protocol = fastParams();
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol, &backend->registry, &backend->throttle);
    monitor = std::make_unique<HeartbeatMonitor>(server.get(), &backend->registry);
    chunks = std::make_unique<ChunkService>(server.get(), config.protocol);
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
      // 记下设备发来的 ERROR 和 CHUNK_REQ 的 from_index，断言用
      QObject::connect(s, &Session::frameReceived, [this](Session*, const Frame& f) {
        if (static_cast<MsgType>(f.type) != MsgType::ChunkReq) return;
        ChunkRequest r;
        if (parseChunkRequest(f.body, &r)) fromIndexes.append(r.fromIndex);
      });
    });
    EXPECT_TRUE(server->start());
  }
  quint16 port() const { return server->serverPort(); }
  Session* sessionOf(const QString& deviceId) const {
    for (Session* s : server->sessions()) {
      if (s->deviceId() == deviceId && s->state() == Session::State::Online) return s;
    }
    return nullptr;
  }

  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ManifestVerifier verifier = trustedVerifier();
  FirmwareRepo repo{verifier};
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  std::unique_ptr<HeartbeatMonitor> monitor;
  std::unique_ptr<ChunkService> chunks;
  QList<int> fromIndexes;
};

// 一台设备：TcpClient + Downloader + ResumeStore，接线方式和客户端主程序一样。
struct Device {
  Device(quint16 port, const Identity& identity, const QString& deviceId, const QString& dataDir)
      : security(sharedPki().pki.security(identity)), store(dataDir + QStringLiteral("/download"), 4) {
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
      o.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
      return o;
    });
    downloader = std::make_unique<Downloader>(
        deviceId, validator, &store, c.protocol,
        [this](MsgType type, const QByteArray& body) { return client->send(type, body); });
    // 心跳里带上下载状态和进度，服务端界面的“升级状态 / 进度”两列就来自这里
    client->setHeartbeatProvider([this]() {
      QJsonObject hb;
      hb.insert(QStringLiteral("state"), downloader->stateName());
      hb.insert(QStringLiteral("progress"), downloader->progress());
      return hb;
    });
    QObject::connect(client.get(), &TcpClient::frameReceived, downloader.get(), &Downloader::handleFrame);
    QObject::connect(client.get(), &TcpClient::stateChanged, downloader.get(), [this](TcpClient::State s) {
      downloader->setOnline(s == TcpClient::State::Online);
    });
    QObject::connect(client.get(), &TcpClient::frameReceived, [this](const Frame& f) {
      if (static_cast<MsgType>(f.type) == MsgType::Error) {
        serverErrors.append(QJsonDocument::fromJson(f.body).object().value(QStringLiteral("code")).toInt());
      }
    });
    QObject::connect(downloader.get(), &Downloader::failed, [this](int code, const QString&) { failures.append(code); });
    QObject::connect(downloader.get(), &Downloader::downloadCompleted, [this](const QString& p) { completedPath = p; });
    client->start();
  }
  bool online() const { return client->state() == TcpClient::State::Online; }
  bool downloaded() const { return downloader->state() == Downloader::State::Downloaded; }
  QByteArray downloadedImage() const {
    QFile f(completedPath);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
  }

  std::unique_ptr<TlsChannelSecurity> security;
  ManifestVerifier verifier = trustedVerifier();
  AllowAll antiRollback;
  UpdateValidator validator{verifier, QStringLiteral("PLC-X200"), antiRollback};
  ResumeStore store;
  std::unique_ptr<TcpClient> client;
  std::unique_ptr<Downloader> downloader;
  QList<int> failures;
  QList<int> serverErrors;
  QString completedPath;
};

class ChunkDownload : public ::testing::Test {
 protected:
  ChunkDownload() { backend.registerDevice(sharedPki().dev001); }
  StoredPackage import(Server* fx, const PackageFile& file) {
    StoredPackage package;
    QString error;
    EXPECT_EQ(fx->repo.import(file.path, &package, &error), PackageCheck::Ok) << error.toStdString();
    return package;
  }
  const QString kDev1 = QStringLiteral("DEV-001");
  QTemporaryDir dir;
  fwds_test::ServerBackend backend;
};

}  // namespace

// FT-05：20 片 + 尾片的固件经 TLS 下载完，和原始镜像逐字节一致；服务端设备表能看到状态和进度
TEST_F(ChunkDownload, DownloadsImageOverTls) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 20 * kChunkSize + 4321);
  const StoredPackage package = import(&fx, file);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.sessionOf(kDev1); }));

  ASSERT_TRUE(fx.chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return dev.downloaded(); }, 10000));
  EXPECT_EQ(dev.downloadedImage(), file.image);
  EXPECT_EQ(fx.chunks->chunksSent(), 21);  // 每片只发了一次
  EXPECT_TRUE(dev.failures.isEmpty());

  // 设备通过心跳上报的状态进了设备表
  DeviceRecord record;
  ASSERT_TRUE(waitFor([&]() -> bool {
    backend.registry.find(kDev1, &record);
    return record.upgradeState == QStringLiteral("VERIFYING");
  }));
  EXPECT_EQ(record.progress, 100);
}

// 服务端导入时自己验一遍：被改过的包进不了仓库，也就不会被下发
TEST_F(ChunkDownload, TamperedPackageIsNotImported) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 3 * kChunkSize);
  QFile f(file.path);
  ASSERT_TRUE(f.open(QIODevice::ReadWrite));
  ASSERT_TRUE(f.seek(f.size() - 5));
  f.write("X", 1);
  f.close();
  StoredPackage package;
  QString error;
  EXPECT_EQ(fx.repo.import(file.path, &package, &error), PackageCheck::ImageMismatch);
  EXPECT_FALSE(fx.repo.find(file.manifest.pkgId, &package));
}

// 离线设备不下发：assign 返回 false，设备之后上线也不会收到通知（不缓存、不盲发）
TEST_F(ChunkDownload, OfflineDeviceIsNotAssigned) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 2 * kChunkSize);
  const StoredPackage package = import(&fx, file);
  EXPECT_FALSE(fx.chunks->assign(kDev1, 12, package));
  EXPECT_TRUE(fx.chunks->assignedPackage(kDev1).isEmpty());

  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online(); }));
  spin(200);
  EXPECT_EQ(dev.downloader->state(), Downloader::State::Idle);
}

// FT-06：下载到约一半时服务端断开这条连接 → 设备自动重连、登录，收到同一个包的通知后
// 从断点继续（from_index > 0），最终成功；总下载量不超过固件片数加一个窗口
TEST_F(ChunkDownload, ResumesAfterConnectionDrop) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 40 * kChunkSize + 99);
  const StoredPackage package = import(&fx, file);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.sessionOf(kDev1); }));

  // 进度第一次到 47% 以上时，从服务端掐断连接
  bool dropped = false;
  int progressAtDrop = 0;
  QObject::connect(dev.downloader.get(), &Downloader::progressChanged, [&](int percent) {
    if (dropped || percent < 47) return;
    dropped = true;
    progressAtDrop = percent;
    QTimer::singleShot(0, [&]() {
      if (Session* s = fx.sessionOf(kDev1)) s->close(QStringLiteral("测试：模拟断网"));
    });
  });
  ASSERT_TRUE(fx.chunks->assign(kDev1, 12, package));

  ASSERT_TRUE(waitFor([&]() { return dropped && !dev.online(); }, 10000));
  const int requestsBeforeDrop = fx.fromIndexes.size();
  ASSERT_TRUE(waitFor([&]() { return dev.downloaded(); }, 10000));

  EXPECT_EQ(dev.downloadedImage(), file.image);
  EXPECT_TRUE(dev.failures.isEmpty());
  // 重连后的第一个请求不是从 0 开始
  ASSERT_GT(fx.fromIndexes.size(), requestsBeforeDrop);
  EXPECT_GT(fx.fromIndexes.at(requestsBeforeDrop), 0);
  EXPECT_GE(fx.fromIndexes.at(requestsBeforeDrop), 41 * progressAtDrop / 100 - 4);
  EXPECT_LE(fx.chunks->chunksSent(), 41 + 4);
}

// 服务端整个停掉再启动（同一端口）：设备端事件循环照常运转（界面不会卡死），
// 进度保留在盘上；服务端恢复、操作员重新下发后，从断点继续
TEST_F(ChunkDownload, SurvivesServerRestart) {
  auto fx = std::make_unique<Server>(&backend);
  const quint16 port = fx->port();
  const PackageFile file(dir, QStringLiteral("fw"), 60 * kChunkSize);
  StoredPackage package = import(fx.get(), file);
  Device dev(port, sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx->sessionOf(kDev1); }));

  // 进度到 30% 时把服务端整个销毁（相当于服务端进程退出）
  bool stopping = false;
  QObject::connect(dev.downloader.get(), &Downloader::progressChanged, [&](int percent) {
    if (stopping || percent < 30) return;
    stopping = true;
    QTimer::singleShot(0, [&]() { fx.reset(); });
  });
  ASSERT_TRUE(fx->chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return !fx; }, 10000));

  // 服务端不在的这段时间：设备端的定时器照常触发，Downloader 停在 DOWNLOADING 等待续传
  int ticks = 0;
  QTimer ticker;
  QObject::connect(&ticker, &QTimer::timeout, [&]() { ++ticks; });
  ticker.start(10);
  ASSERT_TRUE(waitFor([&]() { return !dev.online(); }));
  spin(300);
  EXPECT_GE(ticks, 10);
  EXPECT_EQ(dev.downloader->state(), Downloader::State::Downloading);
  const int doneWhileDown = dev.store.bitmap().doneCount();
  EXPECT_GE(doneWhileDown, 18);
  EXPECT_LT(doneWhileDown, 60);

  // 服务端恢复。重启后下发记录不在了（发布恢复为“已暂停”），设备上线后不会自动收到通知
  fx = std::make_unique<Server>(&backend, port);
  package = import(fx.get(), file);
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx->sessionOf(kDev1); }, 5000));
  spin(100);
  EXPECT_EQ(dev.store.bitmap().doneCount(), doneWhileDown);

  // 操作员继续发布：重新下发同一个包，设备从断点接着下
  ASSERT_TRUE(fx->chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return dev.downloaded(); }, 10000));
  EXPECT_EQ(dev.downloadedImage(), file.image);
  ASSERT_FALSE(fx->fromIndexes.isEmpty());
  EXPECT_GE(fx->fromIndexes.first(), doneWhileDown - 4);
  EXPECT_LE(fx->chunks->chunksSent(), 60 - doneWhileDown + 4);
}

// ST-11（登录后部分）：请求没有下发给自己的包 → 3009；越界 → 3010；格式不对 → 1005。连接都不断开
TEST_F(ChunkDownload, ServerRejectsUnassignedAndOutOfRangeRequests) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 3 * kChunkSize);
  const StoredPackage package = import(&fx, file);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.sessionOf(kDev1); }));
  const QString pkgId = file.manifest.pkgId;
  const auto request = [&](const QString& id, int from, int count) {
    dev.client->send(MsgType::ChunkReq, encodeChunkRequest({id, from, count}));
  };
  const auto waitErrors = [&](int n) { return waitFor([&]() { return dev.serverErrors.size() >= n; }); };

  // 仓库里有这个包，但没有下发给本设备
  request(pkgId, 0, 1);
  ASSERT_TRUE(waitErrors(1));
  EXPECT_EQ(dev.serverErrors.last(), 3009);

  ASSERT_TRUE(fx.chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return dev.downloaded(); }));
  const qint64 sentAfterDownload = fx.chunks->chunksSent();

  request(QStringLiteral("00000000-0000-4000-8000-000000000000"), 0, 1);  // 别的包
  ASSERT_TRUE(waitErrors(2));
  EXPECT_EQ(dev.serverErrors.last(), 3009);
  request(pkgId, 3, 1);  // 只有第 0 ~ 2 片
  ASSERT_TRUE(waitErrors(3));
  EXPECT_EQ(dev.serverErrors.last(), 3010);
  request(pkgId, 2, 2);  // 跨过末尾
  ASSERT_TRUE(waitErrors(4));
  EXPECT_EQ(dev.serverErrors.last(), 3010);
  request(pkgId, 0, 0);  // count 至少为 1
  ASSERT_TRUE(waitErrors(5));
  EXPECT_EQ(dev.serverErrors.last(), 3010);
  request(pkgId, 0, 17);  // 超过窗口上限
  ASSERT_TRUE(waitErrors(6));
  EXPECT_EQ(dev.serverErrors.last(), 3010);
  request(pkgId, 2147483647, 2);  // from_index + count 会溢出
  ASSERT_TRUE(waitErrors(7));
  EXPECT_EQ(dev.serverErrors.last(), 3010);
  dev.client->send(MsgType::ChunkReq, "{\"pkg_id\":1}");
  ASSERT_TRUE(waitErrors(8));
  EXPECT_EQ(dev.serverErrors.last(), 1005);

  EXPECT_EQ(fx.chunks->chunksSent(), sentAfterDownload);  // 被拒绝的请求一片都没发
  EXPECT_TRUE(dev.online());

  // 取消下发之后，原来能要的包也要不到了
  ASSERT_TRUE(fx.chunks->cancel(kDev1, QStringLiteral("emergency_stop")));
  request(pkgId, 0, 1);
  ASSERT_TRUE(waitErrors(9));
  EXPECT_EQ(dev.serverErrors.last(), 3009);
}

// 流控：设备一口气发 200 个请求却不等数据。服务端最多为它缓存两个窗口，其余请求不理会，
// 不会把 200 × 4 片（约 50 MB）都堆进内存
TEST_F(ChunkDownload, ServerDoesNotBufferUnboundedChunks) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 8 * kChunkSize);
  const StoredPackage package = import(&fx, file);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.sessionOf(kDev1); }));
  ASSERT_TRUE(fx.chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return dev.downloaded(); }));
  const qint64 before = fx.chunks->chunksSent();

  for (int i = 0; i < 200; ++i) {
    dev.client->send(MsgType::ChunkReq, encodeChunkRequest({file.manifest.pkgId, 0, 4}));
  }
  spin(500);
  EXPECT_GT(fx.chunks->chunksSent(), before);            // 开头的几个请求照常服务
  EXPECT_LT(fx.chunks->chunksSent() - before, 200 * 4);  // 后面积压时的请求没有再读盘、再排队
  EXPECT_TRUE(dev.online());
}

// 紧急停止：下载中取消 → 设备收到 UPDATE_CANCEL，停止并删除临时文件（3012）
TEST_F(ChunkDownload, CancelDuringDownload) {
  Server fx(&backend);
  const PackageFile file(dir, QStringLiteral("fw"), 60 * kChunkSize);
  const StoredPackage package = import(&fx, file);
  Device dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(waitFor([&]() { return dev.online() && fx.sessionOf(kDev1); }));

  bool cancelled = false;
  QObject::connect(dev.downloader.get(), &Downloader::progressChanged, [&](int percent) {
    if (cancelled || percent < 20) return;
    cancelled = true;
    fx.chunks->cancel(kDev1, QStringLiteral("emergency_stop"));
  });
  ASSERT_TRUE(fx.chunks->assign(kDev1, 12, package));
  ASSERT_TRUE(waitFor([&]() { return !dev.failures.isEmpty(); }, 10000));
  EXPECT_EQ(dev.failures.first(), 3012);
  EXPECT_FALSE(QFile::exists(dev.store.statePath()));
  EXPECT_LT(fx.chunks->chunksSent(), 60);
  EXPECT_TRUE(dev.online());  // 3xxx 不断开连接
}
