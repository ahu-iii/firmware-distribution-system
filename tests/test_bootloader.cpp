// Bootloader 的单元测试（设计 4.5 节流程图，UT-11；ST-22、FT-14 在函数一级的验证）。
// 做法：直接在临时目录里摆好 boot.json 和两个分区的文件，调用 boot()，看结论和 boot.json。
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/business/bootloader.h"
#include "client/business/provisioner.h"
#include "test_device.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class BootloaderTest : public ::testing::Test {
 protected:
  BootResult boot() { return Bootloader(dir.path(), verifier, kTestModel).boot(); }
  QString slotFile(const QString& slot, const QString& name) {
    return QDir(SlotStore(dir.path()).slotDir(slot)).filePath(name);
  }

  QTemporaryDir dir;
  ManifestVerifier verifier = trustedVerifier();
  DeviceFirmware oldFw{QStringLiteral("2.0.0"), 4};
  DeviceFirmware newFw{QStringLiteral("2.1.0"), 5};
};

}  // namespace

// UT-11 ①：没有 pending，启动 active 分区
TEST_F(BootloaderTest, NoPendingBootsActive) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QString(), 0, 4);
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::Normal);
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
  EXPECT_EQ(r.config.active, QStringLiteral("a"));
}

// 新固件验签、自检通过：转正，切换活动分区，提升最小安全版本号，结果写进 boot.json
TEST_F(BootloaderTest, GoodPendingIsConfirmed) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::Upgraded);
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.1.0"));

  const BootConfig saved = readBootConfig(dir.path());
  EXPECT_EQ(saved.active, QStringLiteral("b"));
  EXPECT_TRUE(saved.pending.isEmpty());
  EXPECT_EQ(saved.bootAttempts, 0);
  EXPECT_EQ(saved.minSecurityVersion, 5);
  // 再启动一次：已经没有 pending，照常从 b 启动
  EXPECT_EQ(boot().outcome, BootResult::Outcome::Normal);
}

// UT-11 ②：pending 分区验签失败（镜像被改了一个比特）→ 回滚，3008
TEST_F(BootloaderTest, TamperedPendingRollsBack) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin")), flipBit(newFw.image, 5000));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);

  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::RolledBack);
  EXPECT_EQ(r.code, ErrorCode::BootFailed);
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));  // 旧固件照常运行
  const BootConfig saved = readBootConfig(dir.path());
  EXPECT_EQ(saved.active, QStringLiteral("a"));
  EXPECT_TRUE(saved.pending.isEmpty());
  EXPECT_EQ(saved.minSecurityVersion, 4);  // 没有转正，下限不动
}

// 签名被换成攻击者的签名、manifest 被改：同样回滚
TEST_F(BootloaderTest, ForgedPendingManifestRollsBack) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("manifest.sig")),
            signWith(attackerFsk(), newFw.raw));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);
  EXPECT_EQ(boot().outcome, BootResult::Outcome::RolledBack);

  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("manifest.json")), flipBit(newFw.raw, 20));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);
  EXPECT_EQ(boot().outcome, BootResult::Outcome::RolledBack);
}

// UT-11 ③：签名合法但自检失败的固件 → 回滚，3007（FT-13）
TEST_F(BootloaderTest, SelfTestFailureRollsBack) {
  const DeviceFirmware badFw(QStringLiteral("2.2.0"), 5, 2 * kChunkSize, true);
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  badFw.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);

  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::RolledBack);
  EXPECT_EQ(r.code, ErrorCode::SelftestFailed);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
  EXPECT_EQ(readBootConfig(dir.path()).minSecurityVersion, 4);
}

// UT-11 ④：boot_attempts 超过 3 次 → 回滚，哪怕分区里的固件本身没问题
TEST_F(BootloaderTest, TooManyBootAttemptsRollsBack) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 3, 4);  // 已经试过 3 次
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::RolledBack);
  EXPECT_EQ(r.code, ErrorCode::BootFailed);
  EXPECT_EQ(readBootConfig(dir.path()).active, QStringLiteral("a"));
}

// 第 3 次尝试还在限度之内
TEST_F(BootloaderTest, ThirdAttemptIsStillAllowed) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  newFw.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 2, 4);
  EXPECT_EQ(boot().outcome, BootResult::Outcome::Upgraded);
}

// pending 分区里是别的型号的固件、或安全版本号低于下限的旧固件：Bootloader 自己也查，不转正
TEST_F(BootloaderTest, PendingWithWrongModelOrLowSecurityVersionRollsBack) {
  const DeviceFirmware otherModel(QStringLiteral("2.1.0"), 5, 2 * kChunkSize, false,
                                  QStringLiteral("PLC-OTHER"));
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  otherModel.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);
  EXPECT_EQ(boot().outcome, BootResult::Outcome::RolledBack);

  const DeviceFirmware vulnerable(QStringLiteral("1.9.0"), 3);
  vulnerable.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QStringLiteral("b"), 0, 4);
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::RolledBack);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
}

// FT-14：写入途中断电。分区 b 里只有半个镜像、没有 manifest，boot.json 里没有 pending
TEST_F(BootloaderTest, PowerLossDuringWriteKeepsOldFirmware) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  writeBootConfig(dir.path(), QStringLiteral("a"), QString(), 0, 4);
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin")),
            newFw.image.left(newFw.image.size() / 2));
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::Normal);
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
}

// ST-22：活动分区的固件被改 → 验签失败，切到另一个分区
TEST_F(BootloaderTest, CorruptActiveFallsBackToOtherSlot) {
  const DeviceFirmware sameLevel(QStringLiteral("2.0.1"), 4);
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  sameLevel.installTo(dir.path(), QStringLiteral("b"));
  writeBootConfig(dir.path(), QStringLiteral("b"), QString(), 0, 4);
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin")), flipBit(sameLevel.image, 99));

  const BootResult r = boot();
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
  EXPECT_EQ(readBootConfig(dir.path()).active, QStringLiteral("a"));
}

// 另一个分区里是安全版本号低于下限的旧固件：宁可进恢复模式也不启动它
TEST_F(BootloaderTest, OtherSlotBelowMinimumIsNotBooted) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));  // sv 4
  newFw.installTo(dir.path(), QStringLiteral("b"));  // sv 5，正在运行
  writeBootConfig(dir.path(), QStringLiteral("b"), QString(), 0, 5);
  writeFile(slotFile(QStringLiteral("b"), QStringLiteral("firmware.bin")), flipBit(newFw.image, 99));
  const BootResult r = boot();
  EXPECT_FALSE(r.hasFirmware);  // 恢复模式
}

// 两个分区都是空的（全新设备）：恢复模式，等服务端推送
TEST_F(BootloaderTest, EmptyDeviceEntersRecoveryMode) {
  const BootResult r = boot();
  EXPECT_EQ(r.outcome, BootResult::Outcome::Normal);
  EXPECT_FALSE(r.hasFirmware);
  EXPECT_EQ(r.config.minSecurityVersion, 0);
}

// boot.json 丢失或被写坏：按默认值启动分区 a，并把下限补到正在运行的固件的安全版本号
TEST_F(BootloaderTest, LostBootConfigIsRebuiltFromRunningFirmware) {
  oldFw.installTo(dir.path(), QStringLiteral("a"));
  BootResult r = boot();
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(readBootConfig(dir.path()).minSecurityVersion, 4);

  writeFile(SlotStore(dir.path()).bootConfigPath(), "{ broken");
  r = boot();
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.config.active, QStringLiteral("a"));
  EXPECT_EQ(readBootConfig(dir.path()).minSecurityVersion, 4);
}

// ---- 出厂写入 ----

namespace {

// 用签发工具的同一个函数打一个 .fwpkg。
QString makePackage(const QTemporaryDir& dir, const DeviceFirmware& fw, const QString& name) {
  const QString imagePath = dir.filePath(name + QStringLiteral(".bin"));
  const QString pkgPath = dir.filePath(name + QStringLiteral(".fwpkg"));
  writeFile(imagePath, fw.image);
  FirmwareInfo info;
  info.deviceModel = fw.manifest.deviceModel;
  info.version = fw.manifest.version;
  info.securityVersion = fw.manifest.securityVersion;
  Manifest manifest;
  QString error;
  EXPECT_TRUE(signFirmware(imagePath, info, sharedFsk().key.get(), pkgPath, &manifest, &error))
      << error.toStdString();
  return pkgPath;
}

}  // namespace

TEST_F(BootloaderTest, ProvisionInstallsFactoryFirmware) {
  QTemporaryDir files;
  const QString device = dir.filePath(QStringLiteral("device"));
  const QString pkg = makePackage(files, oldFw, QStringLiteral("factory"));
  QString error;
  ASSERT_TRUE(provisionDevice(device, pkg, verifier, kTestModel, &error)) << error.toStdString();

  const BootResult r = Bootloader(device, verifier, kTestModel).boot();
  ASSERT_TRUE(r.hasFirmware);
  EXPECT_EQ(r.running.version, QStringLiteral("2.0.0"));
  EXPECT_EQ(r.config.active, QStringLiteral("a"));
  EXPECT_EQ(r.config.minSecurityVersion, 4);

  // 只用于空设备：第二次执行被拒绝，现有固件不被覆盖
  const QString pkg2 = makePackage(files, newFw, QStringLiteral("second"));
  EXPECT_FALSE(provisionDevice(device, pkg2, verifier, kTestModel, &error));
  EXPECT_EQ(Bootloader(device, verifier, kTestModel).boot().running.version, QStringLiteral("2.0.0"));
}

TEST_F(BootloaderTest, ProvisionRejectsBadPackages) {
  QTemporaryDir files;
  QString error;
  // 别的型号
  const DeviceFirmware otherModel(QStringLiteral("2.0.0"), 4, 2 * kChunkSize, false,
                                  QStringLiteral("PLC-OTHER"));
  EXPECT_FALSE(provisionDevice(dir.filePath(QStringLiteral("d1")),
                               makePackage(files, otherModel, QStringLiteral("other")), verifier,
                               kTestModel, &error));
  // 被改过一个字节的包
  const QString pkg = makePackage(files, oldFw, QStringLiteral("tampered"));
  QByteArray bytes = readFile(pkg);
  writeFile(pkg, flipBit(bytes, bytes.size() - 10));
  EXPECT_FALSE(provisionDevice(dir.filePath(QStringLiteral("d2")), pkg, verifier, kTestModel, &error));
  // 不是用受信任的 FSK 签的
  ManifestVerifier attacker;
  attacker.loadPublicKey(attackerFsk().publicPem, &error);
  EXPECT_FALSE(provisionDevice(dir.filePath(QStringLiteral("d3")),
                               makePackage(files, oldFw, QStringLiteral("good")), attacker, kTestModel,
                               &error));
}
