// Updater（设备升级状态机）的单元测试：不走网络，测试自己扮演服务端，把帧直接交给 Updater。
// 覆盖：正常升级全流程与分区切换（FT-04、FT-05）、自检失败自动回滚（FT-13）、降级被拒（ST-21）、
// 写入前整包校验（ST-19 整包部分）、取消在各阶段的处理、恢复模式、重启途中进程被杀，
// 以及升级过程变成哪些事件（EventReporter → EventOutbox，协议 5.7 节）。
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTimer>
#include <gtest/gtest.h>

#include "client/business/event_outbox.h"
#include "client/business/event_reporter.h"
#include "client/business/updater.h"
#include "test_device.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

Frame frameOf(MsgType type, const QByteArray& body) {
  Frame f;
  f.type = static_cast<quint8>(type);
  f.body = body;
  return f;
}

class UpdaterTest : public ::testing::Test {
 protected:
  UpdaterTest() {
    config.deviceId = QStringLiteral("DEV-001");
    config.model = kTestModel;
    config.dataDir = dir.filePath(QStringLiteral("device"));
    config.rebootDelayMs = 0;
    config.protocol.chunkWindow = 4;
  }

  // 设备出厂时在分区 a 里装着 2.0.0（安全版本号 4）。
  void installFactoryFirmware() { factory.installTo(config.dataDir, QStringLiteral("a")); }

  // 新建 Updater 并上电（再调一次相当于设备进程重启）。
  void powerOn() {
    updater.reset();
    requests.clear();
    updater = std::make_unique<Updater>(config, verifier,
                                        [this](MsgType type, const QByteArray& body) {
      if (type == MsgType::ChunkReq) {
        ChunkRequest r;
        EXPECT_TRUE(parseChunkRequest(body, &r));
        requests.append(r);
      } else if (type == MsgType::Error) {
        errorsSent.append(QJsonDocument::fromJson(body).object().value(QStringLiteral("code")).toInt());
      }
      return true;
    });
    QObject::connect(updater.get(), &Updater::stateChanged,
                     [this](Updater::State s) { states.append(s); });
    QObject::connect(updater.get(), &Updater::alertRaised,
                     [this](int code, const QString&) { alerts.append(code); });
    QObject::connect(updater.get(), &Updater::finished,
                     [this](const QString& result, int code, const QString&) {
                       results.append(result);
                       resultCodes.append(code);
                     });
    QObject::connect(updater.get(), &Updater::rebootRequested, [this]() { ++rebootsRequested; });
    QObject::connect(updater.get(), &Updater::rebootFinished, [this]() { ++rebootsFinished; });
    updater->powerOn();
    updater->setOnline(true);
  }

  void notify(const DeviceFirmware& fw) {
    updater->handleFrame(frameOf(MsgType::UpdateNotify, fw.notifyBody()));
  }
  void cancel(const DeviceFirmware& fw) {
    UpdateCancel c;
    c.deviceId = config.deviceId;
    c.releaseId = 12;
    c.pkgId = fw.manifest.pkgId;
    c.reason = QStringLiteral("emergency_stop");
    updater->handleFrame(frameOf(MsgType::UpdateCancel, encodeUpdateCancel(c)));
  }
  // 扮演服务端：回应所有分片请求，直到 done() 为真。
  bool serveUntil(const DeviceFirmware& fw, const std::function<bool()>& done) {
    int served = 0;
    return waitFor([&]() {
      while (served < requests.size()) {
        const ChunkRequest r = requests.at(served++);
        for (int i = r.fromIndex; i < r.fromIndex + r.count; ++i) {
          updater->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(r.pkgId, i, fw.chunk(i))));
        }
      }
      return done();
    }, 10000);
  }
  bool serveUntilState(const DeviceFirmware& fw, Updater::State state) {
    return serveUntil(fw, [&]() { return updater->state() == state; });
  }
  QString slotFile(const QString& slot, const QString& name) {
    return QDir(SlotStore(config.dataDir).slotDir(slot)).filePath(name);
  }
  QString partFile(const DeviceFirmware& fw) {
    return QDir(config.dataDir).filePath(QStringLiteral("download/%1.part").arg(fw.manifest.pkgId));
  }

  QTemporaryDir dir;
  ClientConfig config;
  ManifestVerifier verifier = trustedVerifier();
  DeviceFirmware factory{QStringLiteral("2.0.0"), 4};
  std::unique_ptr<Updater> updater;
  QList<ChunkRequest> requests;
  QList<int> errorsSent;
  QList<Updater::State> states;
  QList<int> alerts;
  QStringList results;
  QList<int> resultCodes;
  int rebootsRequested = 0;
  int rebootsFinished = 0;
};

}  // namespace

// FT-04、FT-05：通知 → 下载 → 校验 → 写入 → 重启 → 成功；活动分区从 a 切到 b，分区里的镜像与原件一致
TEST_F(UpdaterTest, FullUpgradeSwitchesSlot) {
  installFactoryFirmware();
  powerOn();
  EXPECT_EQ(updater->state(), Updater::State::Idle);
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("fw_version")).toString(), QStringLiteral("2.0.0"));
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("active_slot")).toString(), QStringLiteral("a"));

  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 9 * kChunkSize + 123);
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Success));

  const QList<Updater::State> expected = {
      Updater::State::Notified, Updater::State::Downloading, Updater::State::Verifying,
      Updater::State::Writing,  Updater::State::Rebooting,   Updater::State::Success};
  EXPECT_EQ(states, expected);
  EXPECT_EQ(results, QStringList{QStringLiteral("SUCCESS")});
  EXPECT_EQ(rebootsRequested, 1);
  EXPECT_EQ(rebootsFinished, 1);
  EXPECT_TRUE(alerts.isEmpty());

  // 新固件在分区 b 运行，镜像一个字节不差；旧固件还原封不动地留在分区 a
  const BootResult& boot = updater->bootState();
  EXPECT_EQ(boot.config.active, QStringLiteral("b"));
  EXPECT_EQ(boot.running.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(boot.config.minSecurityVersion, 5);
  EXPECT_EQ(readFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin"))), fw.image);
  EXPECT_EQ(readFile(slotFile(QStringLiteral("a"), QStringLiteral("firmware.bin"))), factory.image);
  EXPECT_FALSE(QFile::exists(partFile(fw)));  // 下载用的临时文件已删除
  // 重新登录时上报新版本
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("fw_version")).toString(), QStringLiteral("2.1.0"));
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("security_version")).toInt(), 5);
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("active_slot")).toString(), QStringLiteral("b"));

  // 设备重新登录后服务端会把同一个包再通知一次：已经在运行了，不理会，也不当成降级告警
  const int requestsBefore = requests.size();
  notify(fw);
  spin(50);
  EXPECT_EQ(updater->state(), Updater::State::Success);
  EXPECT_EQ(requests.size(), requestsBefore);
  EXPECT_TRUE(alerts.isEmpty());

  // 升级之后，原来的 2.0.0（安全版本号 4）再也装不回去
  notify(factory);
  EXPECT_EQ(updater->state(), Updater::State::Failed);
  EXPECT_EQ(alerts, QList<int>{static_cast<int>(ErrorCode::RollbackAttempt)});
}

// 再升一级：这次写入的是分区 a（当前的非活动分区）
TEST_F(UpdaterTest, SecondUpgradeGoesBackToSlotA) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware first(QStringLiteral("2.1.0"), 5);
  notify(first);
  ASSERT_TRUE(serveUntilState(first, Updater::State::Success));
  const DeviceFirmware second(QStringLiteral("2.2.0"), 5);
  notify(second);
  ASSERT_TRUE(serveUntil(second, [&]() { return results.size() == 2; }));
  EXPECT_EQ(updater->bootState().config.active, QStringLiteral("a"));
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.2.0"));
}

// FT-13：签名合法但自检失败的固件 → 重启后自动回到原分区，版本不变，上报 ROLLED_BACK
TEST_F(UpdaterTest, SelfTestFailureRollsBack) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware bad(QStringLiteral("2.2.0"), 5, 5 * kChunkSize, true);
  notify(bad);
  ASSERT_TRUE(serveUntilState(bad, Updater::State::RolledBack));

  EXPECT_EQ(results, QStringList{QStringLiteral("ROLLED_BACK")});
  EXPECT_EQ(resultCodes, QList<int>{static_cast<int>(ErrorCode::SelftestFailed)});
  const BootResult& boot = updater->bootState();
  ASSERT_TRUE(boot.hasFirmware);
  EXPECT_EQ(boot.config.active, QStringLiteral("a"));
  EXPECT_EQ(boot.running.version, QStringLiteral("2.0.0"));
  EXPECT_EQ(boot.config.minSecurityVersion, 4);  // 没转正，下限不提升
  EXPECT_EQ(rebootsFinished, 1);                 // 回滚后设备重新连接，继续在线

  // 重新登录后服务端重发同一个包的通知：不再重复“写入、重启、回滚”
  const int requestsBefore = requests.size();
  notify(bad);
  spin(50);
  EXPECT_EQ(updater->state(), Updater::State::RolledBack);
  EXPECT_EQ(requests.size(), requestsBefore);

  // 设备没有变砖：换一个好的固件照样能升级
  const DeviceFirmware good(QStringLiteral("2.2.1"), 5);
  notify(good);
  ASSERT_TRUE(serveUntilState(good, Updater::State::Success));
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.2.1"));
}

// ST-21：签名合法的旧固件（1.9.0，安全版本号 3）被 3003 拒绝，一个分片都不下载
TEST_F(UpdaterTest, DowngradeIsRejectedBeforeDownload) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware oldFw(QStringLiteral("1.9.0"), 3);
  notify(oldFw);
  spin(50);
  EXPECT_EQ(updater->state(), Updater::State::Failed);
  EXPECT_TRUE(requests.isEmpty());
  EXPECT_EQ(alerts, QList<int>{static_cast<int>(ErrorCode::RollbackAttempt)});
  EXPECT_EQ(resultCodes, QList<int>{static_cast<int>(ErrorCode::RollbackAttempt)});
  // 版本号更高但安全版本号低于下限：同样拒绝
  const DeviceFirmware lowSv(QStringLiteral("3.0.0"), 3);
  notify(lowSv);
  EXPECT_EQ(alerts.size(), 2);
  EXPECT_TRUE(requests.isEmpty());
}

// ST-19（整包部分）：分片收齐后、写入前，下载文件在磁盘上被改 → 3005，不写入，删除临时文件
TEST_F(UpdaterTest, TamperedDownloadIsNotWritten) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 6 * kChunkSize);
  // 一进入 VERIFYING 就改掉下载文件里的一个字节
  QObject::connect(updater.get(), &Updater::stateChanged, [&](Updater::State s) {
    if (s != Updater::State::Verifying) return;
    QFile part(partFile(fw));
    ASSERT_TRUE(part.open(QIODevice::ReadWrite));
    ASSERT_TRUE(part.seek(4 * kChunkSize + 7));
    part.write("X");
  });
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Failed));

  EXPECT_EQ(alerts, QList<int>{static_cast<int>(ErrorCode::ImageTampered)});
  EXPECT_EQ(resultCodes, QList<int>{static_cast<int>(ErrorCode::ImageTampered)});
  EXPECT_FALSE(states.contains(Updater::State::Writing));
  EXPECT_FALSE(QFile::exists(slotFile(QStringLiteral("b"), QStringLiteral("manifest.json"))));
  EXPECT_FALSE(QFile::exists(partFile(fw)));
  EXPECT_TRUE(readBootConfig(config.dataDir).pending.isEmpty());
  EXPECT_EQ(rebootsRequested, 0);
}

// 写入前（VERIFYING）收到取消：放弃升级，删除临时文件，3012
TEST_F(UpdaterTest, CancelDuringVerifyingAbortsUpdate) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 40 * kChunkSize);  // 校验要分 3 段做
  QObject::connect(updater.get(), &Updater::stateChanged, [&](Updater::State s) {
    if (s == Updater::State::Verifying) QTimer::singleShot(0, [&]() { cancel(fw); });
  });
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Failed));
  EXPECT_EQ(resultCodes, QList<int>{static_cast<int>(ErrorCode::Cancelled)});
  EXPECT_TRUE(alerts.isEmpty());
  EXPECT_FALSE(states.contains(Updater::State::Writing));
  EXPECT_FALSE(QFile::exists(partFile(fw)));
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.0.0"));
}

// 已经进入 WRITING 之后的取消不处理：照常写完并重启；期间别的包的通知回 3013 BUSY
TEST_F(UpdaterTest, CancelAfterWritingStartedIsIgnored) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 40 * kChunkSize);
  const DeviceFirmware another(QStringLiteral("2.3.0"), 5);
  QObject::connect(updater.get(), &Updater::stateChanged, [&](Updater::State s) {
    if (s != Updater::State::Writing) return;
    QTimer::singleShot(0, [&]() {
      cancel(fw);
      notify(another);
      notify(fw);  // 同一个包的重复通知：不理会
    });
  });
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Success));
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(errorsSent, QList<int>{static_cast<int>(ErrorCode::Busy)});
}

// 恢复模式：两个分区都没有可启动的固件，设备照样上线，服务端推送一个固件就能恢复
TEST_F(UpdaterTest, RecoveryModeAcceptsPushedFirmware) {
  powerOn();
  EXPECT_FALSE(updater->bootState().hasFirmware);
  EXPECT_EQ(updater->loginFields().value(QStringLiteral("fw_version")).toString(), QString());

  notify(factory);
  ASSERT_TRUE(serveUntilState(factory, Updater::State::Success));
  ASSERT_TRUE(updater->bootState().hasFirmware);
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.0.0"));
}

// 已写入、已登记 pending，但重启途中进程被杀（或断电）：下次上电由 Bootloader 把升级走完并报告结果
TEST_F(UpdaterTest, InterruptedRebootIsCompletedOnNextPowerOn) {
  installFactoryFirmware();
  config.rebootDelayMs = 60000;  // 让它停在 REBOOTING
  powerOn();
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5);
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Rebooting));
  EXPECT_EQ(readBootConfig(config.dataDir).pending, QStringLiteral("b"));
  EXPECT_TRUE(results.isEmpty());

  powerOn();  // 进程重启
  EXPECT_EQ(updater->state(), Updater::State::Success);
  EXPECT_EQ(results, QStringList{QStringLiteral("SUCCESS")});
  EXPECT_EQ(updater->bootState().config.active, QStringLiteral("b"));
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.1.0"));
}

// 下载、校验途中进程被杀：pending 没有登记，下次上电仍是旧固件；服务端重发通知后从断点接着来
TEST_F(UpdaterTest, RestartBeforeWriteKeepsOldFirmwareAndResumes) {
  installFactoryFirmware();
  powerOn();
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 12 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(waitFor([&]() { return requests.size() >= 1; }));
  // 只回应第一个窗口（4 片），然后“断电”
  const ChunkRequest first = requests.at(0);
  for (int i = first.fromIndex; i < first.fromIndex + first.count; ++i) {
    updater->handleFrame(frameOf(MsgType::ChunkData, encodeChunkData(first.pkgId, i, fw.chunk(i))));
  }

  powerOn();
  EXPECT_EQ(updater->state(), Updater::State::Idle);
  EXPECT_EQ(updater->bootState().running.version, QStringLiteral("2.0.0"));
  notify(fw);
  ASSERT_TRUE(waitFor([&]() { return requests.size() >= 1; }));
  EXPECT_EQ(requests.at(0).fromIndex, 4);  // 前 4 片不用重下
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Success));
  EXPECT_EQ(readFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin"))), fw.image);
}

// ---------------- 升级过程上报的事件 ----------------

namespace {

// 把 Updater 的事件记进一个不在线的 outbox（只落盘），返回所有事件的 (类型, 消息体)
struct RecordedEvents {
  explicit RecordedEvents(Updater* updater, const QString& dir)
      : outbox(dir, [](MsgType, const QByteArray&) { return false; }), reporter(updater, &outbox) {
    QString error;
    EXPECT_TRUE(outbox.open(&error)) << error.toStdString();
  }
  QStringList progressStates() const {
    QStringList states;
    for (const EventOutbox::Event& e : outbox.pending()) {
      if (e.type == MsgType::Progress) {
        const QString state = e.body.value(QStringLiteral("state")).toString();
        if (states.isEmpty() || states.last() != state) states.append(state);
      }
    }
    return states;
  }
  EventOutbox outbox;
  EventReporter reporter;
};

}  // namespace

// 正常升级：每个阶段一条 PROGRESS（下载、写入阶段按 5% 再报），最后一条 RESULT SUCCESS，
// 带发布号、包 ID 和升级后运行的版本；序号从 1 开始连续
TEST_F(UpdaterTest, FullUpgradeIsReportedAsEvents) {
  installFactoryFirmware();
  powerOn();
  RecordedEvents events(updater.get(), dir.filePath(QStringLiteral("outbox")));
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 40 * kChunkSize);
  notify(fw);
  ASSERT_TRUE(serveUntilState(fw, Updater::State::Success));

  const QList<EventOutbox::Event>& all = events.outbox.pending();
  for (int i = 0; i < all.size(); ++i) EXPECT_EQ(all.at(i).seq, i + 1);
  EXPECT_EQ(events.progressStates(),
            (QStringList{QStringLiteral("NOTIFIED"), QStringLiteral("DOWNLOADING"),
                         QStringLiteral("VERIFYING"), QStringLiteral("WRITING"),
                         QStringLiteral("REBOOTING")}));
  int downloading = 0;
  for (const EventOutbox::Event& e : all) {
    if (e.body.value(QStringLiteral("state")).toString() == QLatin1String("DOWNLOADING")) ++downloading;
    if (e.type == MsgType::Progress) EXPECT_EQ(e.body.value(QStringLiteral("pkg_id")).toString(), fw.manifest.pkgId);
  }
  EXPECT_GE(downloading, 10);  // 40 片，每涨 5% 一条
  EXPECT_LE(downloading, 21);

  const EventOutbox::Event& last = all.last();
  ASSERT_EQ(last.type, MsgType::Result);
  EXPECT_EQ(last.body.value(QStringLiteral("result")).toString(), QStringLiteral("SUCCESS"));
  EXPECT_EQ(last.body.value(QStringLiteral("release_id")).toInteger(), 12);
  EXPECT_EQ(last.body.value(QStringLiteral("pkg_id")).toString(), fw.manifest.pkgId);
  EXPECT_EQ(last.body.value(QStringLiteral("fw_version")).toString(), QStringLiteral("2.1.0"));
  EXPECT_EQ(last.body.value(QStringLiteral("active_slot")).toString(), QStringLiteral("b"));
}

// 降级被拒：先 ALERT 3003，再 RESULT FAILED 3003，运行版本仍是原来的 2.0.0；不报 PROGRESS
TEST_F(UpdaterTest, RejectedDowngradeIsReportedAsAlertThenResult) {
  installFactoryFirmware();
  powerOn();
  RecordedEvents events(updater.get(), dir.filePath(QStringLiteral("outbox")));
  const DeviceFirmware oldFw(QStringLiteral("1.9.0"), 3);
  notify(oldFw);
  spin(20);

  const QList<EventOutbox::Event>& all = events.outbox.pending();
  ASSERT_EQ(all.size(), 2);
  EXPECT_EQ(all.at(0).type, MsgType::Alert);
  EXPECT_EQ(all.at(0).body.value(QStringLiteral("code")).toInt(), 3003);
  EXPECT_EQ(all.at(0).body.value(QStringLiteral("pkg_id")).toString(), oldFw.manifest.pkgId);
  EXPECT_EQ(all.at(1).type, MsgType::Result);
  EXPECT_EQ(all.at(1).body.value(QStringLiteral("result")).toString(), QStringLiteral("FAILED"));
  EXPECT_EQ(all.at(1).body.value(QStringLiteral("code")).toInt(), 3003);
  EXPECT_EQ(all.at(1).body.value(QStringLiteral("fw_version")).toString(), QStringLiteral("2.0.0"));
}
