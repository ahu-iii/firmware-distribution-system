// 客户端演示面板背后的动作（设计第 6 节）：
//   模拟断网  TcpClient::setNetworkBlocked：断开后不再连上，恢复后立即重连；升级中断网，恢复后从断点续完
//   篡改缓存  tamperDownloadCache：改掉 .part 的第一个字节；断网期间改了，续传前重验能发现并重下那一片
//   模拟断电  simulatePowerLoss：进程当场以 99 退出
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/business/demo_actions.h"
#include "tests/test_device.h"
#include "tests/test_live.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class DemoPanelTest : public ::testing::Test {
 protected:
  DemoPanelTest() { backend.registerDevice(sharedPki().dev001); }

  bool online(bool expected) {
    return waitFor([&]() {
      DeviceRecord record;
      return backend.registry.find(kDev1, &record) && record.online == expected &&
             (!expected || !record.upgradeState.isEmpty());
    });
  }

  const QString kDev1 = QStringLiteral("DEV-001");
  QTemporaryDir dir;
  ServerBackend backend;
  QString error;
};

}  // namespace

TEST(DemoActions, TamperFlipsFirstByteOfNewestPart) {
  QTemporaryDir dir;
  QString detail;
  EXPECT_FALSE(tamperDownloadCache(dir.path(), &detail));  // 没有 download/ 目录
  ASSERT_TRUE(QDir(dir.path()).mkpath(QStringLiteral("download")));
  QFile part(dir.filePath(QStringLiteral("download/abc.part")));
  ASSERT_TRUE(part.open(QIODevice::WriteOnly));
  part.write(QByteArray("\x0f\x22\x33", 3));
  part.close();

  ASSERT_TRUE(tamperDownloadCache(dir.path(), &detail)) << detail.toStdString();
  EXPECT_TRUE(detail.contains(QStringLiteral("abc.part")));
  ASSERT_TRUE(part.open(QIODevice::ReadOnly));
  EXPECT_EQ(part.readAll(), QByteArray("\xf0\x22\x33", 3));
}

TEST(DemoActions, PowerLossEndsProcessImmediately) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_EXIT(simulatePowerLoss(), ::testing::ExitedWithCode(kPowerLossExitCode), "");
}

// 断网：连接立刻断开，服务端看到离线，之后一直连不上；恢复网络后马上重新登录
TEST_F(DemoPanelTest, BlockedNetworkStaysOfflineUntilRestored) {
  LiveServer fx(&backend);
  LiveDevice dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(online(true));

  dev.client->setNetworkBlocked(true);
  ASSERT_TRUE(online(false));
  spin(500);  // 重连间隔只有 30 ms，这段时间里会“重连”很多次，都不应该连上
  EXPECT_NE(dev.client->state(), TcpClient::State::Online);
  EXPECT_EQ(fx.server->sessions().size(), 0);

  dev.client->setNetworkBlocked(false);
  EXPECT_TRUE(online(true));
}

// 升级下载到一半断网，断网期间篡改下载缓存，恢复网络：续传前重验发现第 0 片坏了，
// 重新下载这一片，升级照常成功
TEST_F(DemoPanelTest, DownloadResumesAfterBlockAndTamperedChunkIsRefetched) {
  LiveServer fx(&backend);
  const DeviceFirmware fw(QStringLiteral("2.1.0"), 5, 40 * kChunkSize);
  Manifest manifest;
  backend.importFirmware(packageFileFor(fw, dir.path(), QStringLiteral("fw"), &manifest));
  LiveDevice dev(fx.port(), sharedPki().dev001, kDev1, dir.filePath(QStringLiteral("dev1")));
  ASSERT_TRUE(online(true));
  backend.openGateAndLoginAsOperator();

  // 下载进度一过 20% 就断网
  QObject::connect(dev.updater.get(), &Updater::progressChanged, [&](int percent) {
    if (dev.updater->state() == Updater::State::Downloading && percent >= 20) {
      dev.client->setNetworkBlocked(true);
    }
  });
  ASSERT_TRUE(backend.admin.dispatchFirmware(manifest.pkgId, kDev1, pwd("Oper-pass-01"), &error))
      << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return dev.client->networkBlocked(); }, 10000));
  ASSERT_TRUE(online(false));
  EXPECT_EQ(dev.updater->state(), Updater::State::Downloading);  // 断点保留，等着续传
  const qint64 sentBefore = fx.chunks->chunksSent();
  EXPECT_LT(sentBefore, manifest.chunkCount);

  QString detail;
  ASSERT_TRUE(tamperDownloadCache(dev.config.dataDir, &detail)) << detail.toStdString();
  QObject::disconnect(dev.updater.get(), &Updater::progressChanged, nullptr, nullptr);
  dev.client->setNetworkBlocked(false);

  ASSERT_TRUE(waitFor([&]() { return dev.updater->state() == Updater::State::Success; }, 20000));
  EXPECT_EQ(dev.runningVersion(), QStringLiteral("2.1.0"));
  // 续传：总共发出的分片 = 片数 + 被篡改的那一片（不是从头再来一遍）
  EXPECT_EQ(fx.chunks->chunksSent(), manifest.chunkCount + 1);
}
