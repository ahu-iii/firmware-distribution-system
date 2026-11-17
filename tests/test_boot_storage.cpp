// 设备端存储层的单元测试：boot.json 的读写与内容检查、分区写入的顺序、模拟镜像头、
// 固件签名公钥的指纹核对。
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/security/fsk_public_key.h"
#include "test_device.h"

using namespace fwds;
using namespace fwds_test;

TEST(BootConfigTest, SavesAndLoads) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("boot.json"));
  BootConfig config;
  EXPECT_EQ(loadBootConfig(path, &config), BootConfigLoad::Missing);  // 第一次上电

  config.active = QStringLiteral("b");
  config.pending = QStringLiteral("a");
  config.bootAttempts = 2;
  config.minSecurityVersion = 5;
  QString error;
  ASSERT_TRUE(saveBootConfig(path, config, &error)) << error.toStdString();

  BootConfig loaded;
  ASSERT_EQ(loadBootConfig(path, &loaded), BootConfigLoad::Ok);
  EXPECT_EQ(loaded.active, QStringLiteral("b"));
  EXPECT_EQ(loaded.pending, QStringLiteral("a"));
  EXPECT_EQ(loaded.bootAttempts, 2);
  EXPECT_EQ(loaded.minSecurityVersion, 5);
}

// 内容不合规的 boot.json 一律判为损坏，不拿来用
TEST(BootConfigTest, RejectsInvalidContent) {
  QTemporaryDir dir;
  const QString path = dir.filePath(QStringLiteral("boot.json"));
  const QList<QByteArray> badFiles = {
      "not json",
      "[1,2,3]",
      R"({"active":"c","pending":"","boot_attempts":0,"min_security_version":0})",   // 没有分区 c
      R"({"active":"a","pending":"a","boot_attempts":0,"min_security_version":0})",  // pending 不能是 active
      R"({"active":"a","pending":"","boot_attempts":-1,"min_security_version":0})",
      R"({"active":"a","pending":"","boot_attempts":0,"min_security_version":1.5})",
      R"({"active":"a","pending":"","boot_attempts":0})",                            // 缺字段
  };
  for (const QByteArray& content : badFiles) {
    writeFile(path, content);
    BootConfig config;
    config.minSecurityVersion = 77;
    EXPECT_EQ(loadBootConfig(path, &config), BootConfigLoad::Corrupt) << content.constData();
    EXPECT_EQ(config.minSecurityVersion, 77);  // 损坏时不改调用方的对象
  }
}

TEST(SlotNames, OnlyAAndB) {
  EXPECT_TRUE(isSlotName(QStringLiteral("a")));
  EXPECT_TRUE(isSlotName(QStringLiteral("b")));
  EXPECT_FALSE(isSlotName(QStringLiteral("../a")));
  EXPECT_FALSE(isSlotName(QString()));
  EXPECT_EQ(otherSlot(QStringLiteral("a")), QStringLiteral("b"));
  EXPECT_EQ(otherSlot(QStringLiteral("b")), QStringLiteral("a"));
}

// 写分区：一开始就删掉旧 manifest（分区立刻变成“不可启动”），镜像写完、刷盘之后才写新 manifest
TEST(SlotWriterTest, ManifestIsRemovedFirstAndWrittenLast) {
  QTemporaryDir dir;
  const SlotStore store(dir.path());
  const DeviceFirmware oldFw(QStringLiteral("2.0.0"), 4);
  const DeviceFirmware newFw(QStringLiteral("2.1.0"), 5);
  oldFw.installTo(dir.path(), QStringLiteral("b"));
  const QString source = dir.filePath(QStringLiteral("new.part"));
  writeFile(source, newFw.image);

  QByteArray raw;
  QByteArray signature;
  ASSERT_TRUE(store.readManifest(QStringLiteral("b"), &raw, &signature));

  SlotWriter writer;
  QString error;
  ASSERT_TRUE(writer.begin(store.slotDir(QStringLiteral("b")), source, 0, newFw.image.size(), &error))
      << error.toStdString();
  EXPECT_FALSE(store.readManifest(QStringLiteral("b"), &raw, &signature));  // 旧 manifest 已删

  ASSERT_TRUE(writer.copySome(kChunkSize, &error));
  EXPECT_FALSE(writer.atEnd());
  EXPECT_FALSE(writer.finish(newFw.raw, newFw.signature, &error));  // 没写完不能收尾
  EXPECT_FALSE(store.readManifest(QStringLiteral("b"), &raw, &signature));

  while (!writer.atEnd()) ASSERT_TRUE(writer.copySome(kChunkSize, &error));
  ASSERT_TRUE(writer.finish(newFw.raw, newFw.signature, &error)) << error.toStdString();
  ASSERT_TRUE(store.readManifest(QStringLiteral("b"), &raw, &signature));
  EXPECT_EQ(raw, newFw.raw);
  EXPECT_EQ(signature, newFw.signature);
  EXPECT_EQ(readFile(store.imagePath(QStringLiteral("b"))), newFw.image);
}

// 源文件比说好的短（下载文件被截断）：报错，不会把分区标成可启动
TEST(SlotWriterTest, ShortSourceFails) {
  QTemporaryDir dir;
  const SlotStore store(dir.path());
  const QString source = dir.filePath(QStringLiteral("short.part"));
  writeFile(source, QByteArray(1000, 'x'));
  SlotWriter writer;
  QString error;
  ASSERT_TRUE(writer.begin(store.slotDir(QStringLiteral("b")), source, 0, 5000, &error));
  EXPECT_FALSE(writer.copySome(5000, &error));
}

TEST(FirmwareImageTest, HeaderRoundTrip) {
  ImageHeader header;
  header.model = QStringLiteral("PLC-X200");
  header.version = QStringLiteral("2.1.0");
  header.selfTestFails = true;
  const QByteArray bytes = buildImageHeader(header);
  ASSERT_EQ(bytes.size(), kImageHeaderSize);
  EXPECT_TRUE(bytes.startsWith("IFW1"));

  ImageHeader parsed;
  ASSERT_TRUE(parseImageHeader(bytes + "payload", &parsed));
  EXPECT_EQ(parsed.model, header.model);
  EXPECT_EQ(parsed.version, header.version);
  EXPECT_TRUE(parsed.selfTestFails);
}

TEST(FirmwareImageTest, RejectsBadInput) {
  ImageHeader header;
  header.model = QStringLiteral("A-MODEL-NAME-LONGER-THAN-16");
  header.version = QStringLiteral("1.0.0");
  EXPECT_TRUE(buildImageHeader(header).isEmpty());
  header.model = QStringLiteral("型号");  // 非 ASCII
  EXPECT_TRUE(buildImageHeader(header).isEmpty());

  ImageHeader parsed;
  EXPECT_FALSE(parseImageHeader(QByteArray(10, 'x'), &parsed));                // 太短
  EXPECT_FALSE(parseImageHeader(QByteArray(kImageHeaderSize, 'x'), &parsed));  // 魔数不对
  // 自检标志只有 0 算通过
  header.model = QStringLiteral("PLC-X200");
  QByteArray bytes = buildImageHeader(header);
  bytes[36] = '\x07';
  ASSERT_TRUE(parseImageHeader(bytes, &parsed));
  EXPECT_TRUE(parsed.selfTestFails);
}

// 设备只信任指纹和配置一致的那把固件签名公钥
TEST(FskPublicKeyTest, FingerprintMustMatchConfig) {
  QTemporaryDir dir;
  const QString pemPath = dir.filePath(QStringLiteral("fsk.pub.pem"));
  writeFile(pemPath, sharedFsk().publicPem);
  const QString fingerprint = trustedVerifier().publicKeyFingerprint();

  ManifestVerifier verifier;
  QString error;
  ASSERT_TRUE(loadPinnedFskPublicKey(pemPath, fingerprint, &verifier, &error)) << error.toStdString();
  EXPECT_EQ(verifier.publicKeyFingerprint(), fingerprint);

  // 文件被换成攻击者的公钥：指纹对不上，拒绝，验签器里不留任何公钥
  writeFile(pemPath, attackerFsk().publicPem);
  ManifestVerifier other;
  EXPECT_FALSE(loadPinnedFskPublicKey(pemPath, fingerprint, &other, &error));
  EXPECT_TRUE(other.publicKeyFingerprint().isEmpty());
  // 文件不存在、不是公钥
  EXPECT_FALSE(loadPinnedFskPublicKey(dir.filePath(QStringLiteral("nope.pem")), fingerprint, &other, &error));
  writeFile(pemPath, "not a key");
  EXPECT_FALSE(loadPinnedFskPublicKey(pemPath, fingerprint, &other, &error));
}
