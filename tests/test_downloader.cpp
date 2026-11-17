// Downloader 的单元测试：不走网络，测试自己扮演服务端，把帧直接交给 Downloader。
// 覆盖：先验签后下载、逐片校验与单片重试（3004）、窗口超时重发、取消（3012）、忙（3013）、
// 断线暂停与续传、进程重启后从断点继续。对应 FT-05 ~ FT-07、ST-19（分片部分）在函数一级的验证。
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/business/downloader.h"
#include "common/update_messages.h"
#include "test_fsk.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class AllowAll : public AntiRollback {
 public:
  bool allows(const Manifest&, QString* reason) const override {
    if (!allow) *reason = QStringLiteral("security_version too low");
    return allow;
  }
  bool allow = true;
};

// 一份签好名的固件：镜像、manifest 原始字节、签名。
struct Firmware {
  explicit Firmware(int size) : image(randomBytes(size)) {}
  QByteArray chunk(int index) const { return image.mid(index * kChunkSize, kChunkSize); }
  QByteArray notifyBody(const QString& deviceId = QStringLiteral("DEV-001")) const {
    UpdateNotify n;
    n.deviceId = deviceId;
    n.releaseId = 12;
    n.pkgId = manifest.pkgId;
    n.manifestRaw = raw;
    n.signature = signature;
    return encodeUpdateNotify(n);
  }
  QByteArray image;
  Manifest manifest = manifestFor(image);
  QByteArray raw = serializeManifest(manifest);
  QByteArray signature = signWith(sharedFsk(), raw);
};

Frame frameOf(MsgType type, const QByteArray& body) {
  Frame f;
  f.type = static_cast<quint8>(type);
  f.body = body;
  return f;
}

class DownloaderTest : public ::testing::Test {
 protected:
  DownloaderTest() {
    params.chunkWindow = 4;
    params.chunkWindowTimeoutMs = 80;
    params.chunkRetryLimit = 3;
    start();
  }

  // 新建 ResumeStore 和 Downloader（再调一次相当于设备进程重启）。
  void start() {
    downloader.reset();
    store = std::make_unique<ResumeStore>(dir.filePath(QStringLiteral("download")), 4);
    downloader = std::make_unique<Downloader>(
        QStringLiteral("DEV-001"), validator, store.get(), params,
        [this](MsgType type, const QByteArray& body) {
          if (!linkUp) return false;
          if (type == MsgType::ChunkReq) {
            ChunkRequest r;
            EXPECT_TRUE(parseChunkRequest(body, &r));
            requests.append(r);
          } else if (type == MsgType::Error) {
            errorsSent.append(QJsonDocument::fromJson(body).object().value(QStringLiteral("code")).toInt());
          }
          return true;
        });
    QObject::connect(downloader.get(), &Downloader::failed,
                     [this](int code, const QString&) { failures.append(code); });
    QObject::connect(downloader.get(), &Downloader::alertRaised,
                     [this](int code, const QString&) { alerts.append(code); });
    QObject::connect(downloader.get(), &Downloader::downloadCompleted,
                     [this](const QString& path) { completedPath = path; });
    QObject::connect(downloader.get(), &Downloader::progressChanged,
                     [this](int percent) { progress.append(percent); });
    downloader->setOnline(true);
  }

  void notify(const Firmware& fw) {
    downloader->handleFrame(frameOf(MsgType::UpdateNotify, fw.notifyBody()));
  }
  // 等 Downloader 发出第 n 个 CHUNK_REQ（从 1 数）。
  bool waitRequest(int n) { return waitFor([&]() { return requests.size() >= n; }); }
  // 扮演服务端回应一个请求；tamper 指定的那一片翻转 1 比特。
  // 请求按值传入：回应过程中 Downloader 会发出新的请求，requests 列表可能重新分配内存。
  void serve(const Firmware& fw, ChunkRequest r, int tamper = -1) {
    for (int i = r.fromIndex; i < r.fromIndex + r.count; ++i) {
      QByteArray data = fw.chunk(i);
      if (i == tamper) data = flipBit(data, 10);
      downloader->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(r.pkgId, i, data)));
    }
  }
  // 一路正常回应直到下载结束。
  bool serveUntilDone(const Firmware& fw) {
    int served = 0;
    return waitFor([&]() {
      while (served < requests.size()) serve(fw, requests.at(served++));
      return downloader->state() != Downloader::State::Downloading &&
             downloader->state() != Downloader::State::Notified;
    });
  }
  QByteArray readFile(const QString& path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
  }

  QTemporaryDir dir;
  ProtocolParams params;
  ManifestVerifier verifier = trustedVerifier();
  AllowAll antiRollback;
  UpdateValidator validator{verifier, QStringLiteral("PLC-X200"), antiRollback};
  std::unique_ptr<ResumeStore> store;
  std::unique_ptr<Downloader> downloader;
  bool linkUp = true;
  QList<ChunkRequest> requests;
  QList<int> errorsSent;
  QList<int> failures;
  QList<int> alerts;
  QList<int> progress;
  QString completedPath;
};

}  // namespace

// FT-05：10 片的固件按窗口下载完，文件和原镜像完全一致
TEST_F(DownloaderTest, DownloadsWholeImageWindowByWindow) {
  const Firmware fw(9 * kChunkSize + 123);
  notify(fw);
  EXPECT_EQ(downloader->state(), Downloader::State::Notified);
  ASSERT_TRUE(serveUntilDone(fw));

  EXPECT_EQ(downloader->state(), Downloader::State::Downloaded);
  EXPECT_EQ(downloader->stateName(), QStringLiteral("VERIFYING"));
  EXPECT_EQ(readFile(completedPath), fw.image);
  // 窗口为 4：请求依次是 0+4、4+4、8+2
  ASSERT_EQ(requests.size(), 3);
  EXPECT_EQ(requests[0].fromIndex, 0);
  EXPECT_EQ(requests[1].fromIndex, 4);
  EXPECT_EQ(requests[2].fromIndex, 8);
  EXPECT_EQ(requests[2].count, 2);
  EXPECT_EQ(progress.last(), 100);
  EXPECT_TRUE(failures.isEmpty());
}

// 先验签后下载：签名不对时一个 CHUNK_REQ 都不发，也不创建下载文件
TEST_F(DownloaderTest, BadSignatureMeansNoDownload) {
  Firmware fw(3 * kChunkSize);
  fw.signature = signWith(attackerFsk(), fw.raw);  // 攻击者自己的密钥签的
  notify(fw);
  spin(50);
  EXPECT_TRUE(requests.isEmpty());
  EXPECT_EQ(downloader->state(), Downloader::State::Failed);
  EXPECT_EQ(failures, QList<int>{3001});
  EXPECT_EQ(alerts, QList<int>{3001});
  EXPECT_FALSE(QFile::exists(dir.filePath(QStringLiteral("download/") + fw.manifest.pkgId + QStringLiteral(".part"))));

  // manifest 被改了 1 比特，签名还是原来的
  Firmware tampered(3 * kChunkSize);
  tampered.raw = flipBit(tampered.raw, 40);
  notify(tampered);
  EXPECT_EQ(failures.last(), 3001);
  EXPECT_TRUE(requests.isEmpty());
}

// 降级 3003 告警；型号不符 3002 只报失败。都不下载
TEST_F(DownloaderTest, RollbackAndModelMismatchMeanNoDownload) {
  const Firmware fw(2 * kChunkSize);
  antiRollback.allow = false;
  notify(fw);
  EXPECT_EQ(failures, QList<int>{3003});
  EXPECT_EQ(alerts, QList<int>{3003});

  antiRollback.allow = true;
  const UpdateValidator otherModel(verifier, QStringLiteral("GW-100"), antiRollback);
  ResumeStore otherStore(dir.filePath(QStringLiteral("other")));
  Downloader other(QStringLiteral("DEV-001"), otherModel, &otherStore, params,
                   [this](MsgType, const QByteArray&) { requests.append(ChunkRequest()); return true; });
  QList<int> codes;
  QObject::connect(&other, &Downloader::failed, [&](int code, const QString&) { codes.append(code); });
  other.setOnline(true);
  other.handleFrame(frameOf(MsgType::UpdateNotify, fw.notifyBody()));
  EXPECT_EQ(codes, QList<int>{3002});
  spin(30);
  EXPECT_TRUE(requests.isEmpty());
}

// 通知不是发给本设备的：忽略
TEST_F(DownloaderTest, IgnoresNotifyForAnotherDevice) {
  const Firmware fw(2 * kChunkSize);
  downloader->handleFrame(frameOf(MsgType::UpdateNotify, fw.notifyBody(QStringLiteral("DEV-002"))));
  spin(30);
  EXPECT_EQ(downloader->state(), Downloader::State::Idle);
  EXPECT_TRUE(requests.isEmpty());

  downloader->handleFrame(frameOf(MsgType::UpdateNotify, "not json"));
  EXPECT_EQ(errorsSent, QList<int>{1005});
}

// 某一片哈希不符：这一片不写盘，下一个请求只重新要它；后面已经好的分片不重下
TEST_F(DownloaderTest, MismatchedChunkIsRequestedAgain) {
  const Firmware fw(6 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0], 1);  // 第 1 片被改
  ASSERT_TRUE(waitRequest(2));
  EXPECT_EQ(requests[1].fromIndex, 1);
  EXPECT_EQ(requests[1].count, 1);  // 第 2、3 片已经好了，只要第 1 片
  EXPECT_FALSE(store->bitmap().test(1));
  EXPECT_TRUE(store->bitmap().test(2));

  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(downloader->state(), Downloader::State::Downloaded);
  EXPECT_EQ(readFile(completedPath), fw.image);
  EXPECT_TRUE(alerts.isEmpty());
}

// 同一片连续 3 次哈希不符：告警 3004，中止，删除临时文件
TEST_F(DownloaderTest, ThreeMismatchesAbortWith3004) {
  const Firmware fw(6 * kChunkSize);
  notify(fw);
  for (int round = 1; round <= 3; ++round) {
    ASSERT_TRUE(waitRequest(round));
    serve(fw, requests[round - 1], 1);
  }
  EXPECT_EQ(downloader->state(), Downloader::State::Failed);
  EXPECT_EQ(failures, QList<int>{3004});
  EXPECT_EQ(alerts, QList<int>{3004});
  EXPECT_FALSE(QFile::exists(store->statePath()));
  spin(150);  // 过了窗口超时也不再发请求
  EXPECT_EQ(requests.size(), 3);
}

// 不属于当前窗口、不属于当前包、格式不对的 CHUNK_DATA 都丢弃，不影响下载
TEST_F(DownloaderTest, UnexpectedChunkDataIsDropped) {
  const Firmware fw(6 * kChunkSize);
  const Firmware otherFw(6 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  downloader->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(fw.manifest.pkgId, 5, fw.chunk(5))));
  downloader->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(otherFw.manifest.pkgId, 0, otherFw.chunk(0))));
  downloader->handleFrame(frameOf(MsgType::ChunkData, QByteArray(10, 'x')));
  QByteArray wrongLen = encodeChunkData(fw.manifest.pkgId, 0, fw.chunk(0));
  wrongLen.chop(1);  // data_len 和实际长度对不上
  downloader->handleFrame(frameOf(MsgType::ChunkData, wrongLen));
  EXPECT_EQ(store->bitmap().doneCount(), 0);

  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
}

// 一个窗口没收齐：超时后从第一个缺失的分片重新要
TEST_F(DownloaderTest, WindowTimeoutRequestsMissingChunksAgain) {
  const Firmware fw(6 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  // 只回第 0、1 片，第 2、3 片“丢了”
  downloader->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(fw.manifest.pkgId, 0, fw.chunk(0))));
  downloader->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(fw.manifest.pkgId, 1, fw.chunk(1))));
  ASSERT_TRUE(waitRequest(2));  // 80 毫秒后自动重发
  EXPECT_EQ(requests[1].fromIndex, 2);
  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
}

// UPDATE_CANCEL：停止下载，删除临时文件，报 3012
TEST_F(DownloaderTest, CancelStopsAndRemovesFiles) {
  const Firmware fw(6 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0]);
  const QString partPath = store->partPath();

  UpdateCancel cancel{QStringLiteral("DEV-001"), 12, fw.manifest.pkgId, QStringLiteral("emergency_stop")};
  // 针对别的包的取消不理会
  UpdateCancel other = cancel;
  other.pkgId = Firmware(100).manifest.pkgId;
  downloader->handleFrame(frameOf(MsgType::UpdateCancel, encodeUpdateCancel(other)));
  EXPECT_EQ(downloader->state(), Downloader::State::Downloading);

  downloader->handleFrame(frameOf(MsgType::UpdateCancel, encodeUpdateCancel(cancel)));
  EXPECT_EQ(downloader->state(), Downloader::State::Failed);
  EXPECT_EQ(failures, QList<int>{3012});
  EXPECT_TRUE(alerts.isEmpty());
  EXPECT_FALSE(QFile::exists(partPath));
  const int sent = requests.size();
  spin(150);
  EXPECT_EQ(requests.size(), sent);
}

// 下载中收到另一个包的通知：回 3013 BUSY，当前下载不受影响
TEST_F(DownloaderTest, AnotherPackageWhileBusyGets3013) {
  const Firmware fw(6 * kChunkSize);
  const Firmware second(2 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  notify(second);
  EXPECT_EQ(errorsSent, QList<int>{3013});
  notify(fw);  // 同一个包的重复通知：不报错，也不重来
  EXPECT_EQ(errorsSent.size(), 1);
  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
  EXPECT_EQ(requests.size(), 2);
}

// 服务端回 3009：包已不再下发给本设备，停止请求，断点保留
TEST_F(DownloaderTest, ServerPkgNotFoundStopsDownload) {
  const Firmware fw(6 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  downloader->handleFrame(frameOf(MsgType::Error, "{\"code\":3009,\"message\":\"PKG_NOT_FOUND\"}"));
  EXPECT_EQ(failures, QList<int>{3009});
  EXPECT_TRUE(QFile::exists(store->statePath()));
}

// FT-06（同一进程内）：下载到一半断线 → 暂停且进度落盘；重连后收到同一个包的通知 → 从断点继续
TEST_F(DownloaderTest, PausesWhenOfflineAndResumesAfterNotify) {
  const Firmware fw(10 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0]);  // 第 0 ~ 3 片
  ASSERT_TRUE(waitRequest(2));
  serve(fw, {fw.manifest.pkgId, 4, 2});  // 第二个窗口只到了 4、5 两片就断线

  linkUp = false;
  downloader->setOnline(false);
  EXPECT_EQ(downloader->state(), Downloader::State::Downloading);  // 状态保持，等待续传
  // 断线那一刻进度已经落盘：断点记录里是 6 片
  {
    QFile state(store->statePath());
    ASSERT_TRUE(state.open(QIODevice::ReadOnly));
    const QByteArray bits = QByteArray::fromBase64(
        QJsonDocument::fromJson(state.readAll()).object().value(QStringLiteral("bitmap")).toString().toLatin1());
    ChunkBitmap saved;
    ASSERT_TRUE(ChunkBitmap::fromBytes(bits, 10, &saved));
    EXPECT_EQ(saved.doneCount(), 6);
  }
  spin(200);  // 断线期间不发请求，事件循环照常转
  EXPECT_EQ(requests.size(), 2);

  // 重连：上线后先不动，等通知
  linkUp = true;
  downloader->setOnline(true);
  spin(50);
  EXPECT_EQ(requests.size(), 2);
  notify(fw);
  ASSERT_TRUE(waitRequest(3));
  EXPECT_EQ(requests[2].fromIndex, 6);  // from_index = 第一个缺失分片
  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
  EXPECT_TRUE(failures.isEmpty());
}

// FT-06（进程重启）：下载到一半设备进程退出，重新启动后收到通知 → 从断点继续，不从头下
TEST_F(DownloaderTest, ResumesAfterProcessRestart) {
  const Firmware fw(10 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0]);
  ASSERT_TRUE(waitRequest(2));
  serve(fw, requests[1]);  // 8 片已完成
  ASSERT_TRUE(waitRequest(3));

  requests.clear();
  start();  // 旧对象销毁，新对象只能靠盘上的断点
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  EXPECT_EQ(requests[0].fromIndex, 8);
  EXPECT_EQ(requests[0].count, 2);
  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
}

// FT-07 ①：断线期间 .part 里已完成的一片被改 → 续传前重新校验发现，只重下这一片
TEST_F(DownloaderTest, TamperedCacheIsDownloadedAgainOnResume) {
  const Firmware fw(8 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0]);
  ASSERT_TRUE(waitRequest(2));
  linkUp = false;
  downloader->setOnline(false);

  QFile part(store->partPath());
  ASSERT_TRUE(part.open(QIODevice::ReadWrite));
  ASSERT_TRUE(part.seek(2 * kChunkSize));
  part.write("tampered");
  part.close();

  linkUp = true;
  downloader->setOnline(true);
  notify(fw);
  ASSERT_TRUE(waitRequest(3));
  EXPECT_EQ(requests[2].fromIndex, 2);
  EXPECT_EQ(requests[2].count, 1);  // 只重下被改的第 2 片
  ASSERT_TRUE(serveUntilDone(fw));
  EXPECT_EQ(readFile(completedPath), fw.image);
}

// FT-07 ②：断线期间服务端改推另一个包 → 丢弃旧进度，新包从头下载
TEST_F(DownloaderTest, DifferentPackageAfterReconnectStartsOver) {
  const Firmware fw(8 * kChunkSize);
  const Firmware second(5 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitRequest(1));
  serve(fw, requests[0]);
  const QString oldPart = store->partPath();
  linkUp = false;
  downloader->setOnline(false);
  linkUp = true;
  downloader->setOnline(true);

  requests.clear();
  notify(second);
  EXPECT_TRUE(errorsSent.isEmpty());  // 重连后的通知不算“忙”
  ASSERT_TRUE(waitRequest(1));
  EXPECT_EQ(requests[0].pkgId, second.manifest.pkgId);
  EXPECT_EQ(requests[0].fromIndex, 0);
  EXPECT_FALSE(QFile::exists(oldPart));
  ASSERT_TRUE(serveUntilDone(second));
  EXPECT_EQ(readFile(completedPath), second.image);
}
