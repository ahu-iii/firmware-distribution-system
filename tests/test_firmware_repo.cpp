// 服务端固件库（FirmwareRepo + AdminService::importFirmware）的单元测试。
// 对应测试报告 FT-03（固件导入验签：正常包入库，被篡改的包被拒）、
// ST-20 的服务端部分（攻击者密钥签的包进不了库）、ST-12（非维护员不能导入）。
#include <QDir>
#include <QFile>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "tests/test_device.h"
#include "tests/test_server_env.h"

using namespace fwds;
using namespace fwds_test;

namespace {

class FirmwareLibrary : public ::testing::Test {
 protected:
  // 在临时目录里做一个签好名的 .fwpkg（2.1.0，安全版本号 5）。
  QString makePackage(const QString& name, Manifest* manifest) {
    const DeviceFirmware fw(QStringLiteral("2.1.0"), 5);
    return packageFileFor(fw, dir.path(), name, manifest);
  }
  // 固件库目录里现有的文件名。
  static QStringList libraryFiles(const ServerBackend& be) {
    return QDir(be.ownLibraryDir.path()).entryList(QDir::Files);
  }
  static int firmwareRows(ServerBackend* be) {
    QSqlQuery query(be->db.handle());
    query.exec(QStringLiteral("SELECT COUNT(*) FROM firmware"));
    return query.next() ? query.value(0).toInt() : -1;
  }
  // 翻转文件里某个位置的一个比特。offset 为负数时从文件末尾算。
  static void flipByteInFile(const QString& path, qint64 offset) {
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::ReadWrite));
    const qint64 pos = offset >= 0 ? offset : file.size() + offset;
    ASSERT_TRUE(file.seek(pos));
    char byte = 0;
    ASSERT_EQ(file.read(&byte, 1), 1);
    byte = static_cast<char>(byte ^ 0x01);
    ASSERT_TRUE(file.seek(pos));
    file.write(&byte, 1);
  }

  QTemporaryDir dir;
};

}  // namespace

// FT-03：合法的包导入后，固件库目录里有一份以包 ID 命名的副本，固件表里有一行，记着是谁导入的
TEST_F(FirmwareLibrary, ImportCopiesPackageAndRecordsIt) {
  ServerBackend be;
  Manifest manifest;
  const QString path = makePackage(QStringLiteral("fw"), &manifest);
  const StoredPackage package = be.importFirmware(path);

  EXPECT_EQ(package.manifest.pkgId, manifest.pkgId);
  EXPECT_EQ(package.manifest.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(package.importedBy, QStringLiteral("maint"));
  EXPECT_TRUE(package.usable);
  EXPECT_EQ(libraryFiles(be), QStringList{manifest.pkgId + QStringLiteral(".fwpkg")});
  EXPECT_EQ(firmwareRows(&be), 1);

  // 下发时读的是固件库里的副本，不是原文件：原文件删掉也不影响
  EXPECT_NE(package.filePath, path);
  ASSERT_TRUE(QFile::remove(path));
  StoredPackage found;
  ASSERT_TRUE(be.firmware.find(manifest.pkgId, &found));
  EXPECT_TRUE(QFile::exists(found.filePath));
}

// 同一个包导入第二次被拒，固件库不变
TEST_F(FirmwareLibrary, SamePackageIsNotImportedTwice) {
  ServerBackend be;
  Manifest manifest;
  const QString path = makePackage(QStringLiteral("fw"), &manifest);
  be.importFirmware(path);
  QString error;
  EXPECT_FALSE(be.admin.importFirmware(path, &error));
  EXPECT_EQ(firmwareRows(&be), 1);
  EXPECT_EQ(libraryFiles(be).size(), 1);
}

// FT-03、ST-20（服务端部分）：镜像被改了一个比特、manifest 被改了一个比特、用别的密钥签的包，
// 都进不了固件库，目录里也不留下任何文件
TEST_F(FirmwareLibrary, TamperedOrForgedPackagesAreRejected) {
  ServerBackend be;
  be.loginAsMaintainer();
  QString error;
  Manifest manifest;

  const QString imageChanged = makePackage(QStringLiteral("image-changed"), &manifest);
  flipByteInFile(imageChanged, -5);
  EXPECT_FALSE(be.admin.importFirmware(imageChanged, &error));

  const QString manifestChanged = makePackage(QStringLiteral("manifest-changed"), &manifest);
  flipByteInFile(manifestChanged, 20);  // 落在 manifest 的 JSON 里
  EXPECT_FALSE(be.admin.importFirmware(manifestChanged, &error));

  // 攻击者用自己的 RSA-3072 密钥签的包：格式完全正确，只是签名的人不对
  const DeviceFirmware fw(QStringLiteral("9.9.9"), 99);
  const QString imagePath = dir.filePath(QStringLiteral("forged.bin"));
  writeFile(imagePath, fw.image);
  FirmwareInfo info;
  info.deviceModel = kTestModel;
  info.version = QStringLiteral("9.9.9");
  info.securityVersion = 99;
  const QString forged = dir.filePath(QStringLiteral("forged.fwpkg"));
  ASSERT_TRUE(signFirmware(imagePath, info, attackerFsk().key.get(), forged, &manifest, &error));
  EXPECT_FALSE(be.admin.importFirmware(forged, &error));

  // 根本不是固件包的文件
  const QString junk = dir.filePath(QStringLiteral("junk.fwpkg"));
  writeFile(junk, QByteArray(1000, 'x'));
  EXPECT_FALSE(be.admin.importFirmware(junk, &error));
  EXPECT_FALSE(be.admin.importFirmware(dir.filePath(QStringLiteral("missing.fwpkg")), &error));

  EXPECT_EQ(firmwareRows(&be), 0);
  EXPECT_TRUE(be.firmware.packages().isEmpty());
  EXPECT_TRUE(libraryFiles(be).isEmpty());
}

// ST-12：导入固件只有维护员能做。操作员、审计员、没登录的人直接调业务接口都被拒
TEST_F(FirmwareLibrary, OnlyMaintainerCanImport) {
  ServerBackend be;
  Manifest manifest;
  const QString path = makePackage(QStringLiteral("fw"), &manifest);
  QString error;
  EXPECT_FALSE(be.admin.importFirmware(path, &error));  // 没登录

  be.loginAsMaintainer();
  ASSERT_TRUE(be.auth.createAccount(QStringLiteral("oper"), Role::Operator, pwd("Oper-pass-01"), false, &error));
  ASSERT_TRUE(be.auth.createAccount(QStringLiteral("audit"), Role::Auditor, pwd("Audit-pass-01"), false, &error));
  ASSERT_EQ(be.admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &error), AuthResult::Ok);
  EXPECT_FALSE(be.admin.importFirmware(path, &error));
  ASSERT_EQ(be.admin.login(QStringLiteral("audit"), pwd("Audit-pass-01"), &error), AuthResult::Ok);
  EXPECT_FALSE(be.admin.importFirmware(path, &error));

  EXPECT_EQ(firmwareRows(&be), 0);
  EXPECT_TRUE(libraryFiles(be).isEmpty());
}

// 服务端重启后固件库还在：固件表落在数据库文件里，启动时把每个包重新检查一遍
TEST_F(FirmwareLibrary, LibrarySurvivesRestart) {
  const QString dbPath = dir.filePath(QStringLiteral("server.db"));
  const QString libraryPath = dir.filePath(QStringLiteral("library"));
  Manifest manifest;
  const QString path = makePackage(QStringLiteral("fw"), &manifest);
  {
    ServerBackend be(dbPath, libraryPath);
    be.importFirmware(path);
  }
  ServerBackend restarted(dbPath, libraryPath);
  StoredPackage package;
  ASSERT_TRUE(restarted.firmware.find(manifest.pkgId, &package));
  EXPECT_TRUE(package.usable);
  EXPECT_EQ(package.manifest.imageSha256, manifest.imageSha256);
  EXPECT_EQ(package.importedBy, QStringLiteral("maint"));
  EXPECT_FALSE(package.manifestRaw.isEmpty());
  EXPECT_GT(package.imageOffset, 0);
}

// 入库之后固件库里的文件被人动过（或者丢了）：重启后这个包标记为不可用，仍然列出来给维护员看
TEST_F(FirmwareLibrary, PackageChangedOnDiskIsUnusableAfterRestart) {
  const QString dbPath = dir.filePath(QStringLiteral("server.db"));
  const QString libraryPath = dir.filePath(QStringLiteral("library"));
  Manifest tampered;
  Manifest missing;
  QString tamperedFile;
  QString missingFile;
  {
    ServerBackend be(dbPath, libraryPath);
    tamperedFile = be.importFirmware(makePackage(QStringLiteral("a"), &tampered)).filePath;
    missingFile = be.importFirmware(makePackage(QStringLiteral("b"), &missing)).filePath;
  }
  flipByteInFile(tamperedFile, -5);
  ASSERT_TRUE(QFile::remove(missingFile));

  ServerBackend restarted(dbPath, libraryPath);
  EXPECT_EQ(restarted.firmware.packages().size(), 2);
  StoredPackage package;
  ASSERT_TRUE(restarted.firmware.find(tampered.pkgId, &package));
  EXPECT_FALSE(package.usable);
  EXPECT_FALSE(package.problem.isEmpty());
  EXPECT_EQ(package.manifest.version, QStringLiteral("2.1.0"));  // 列表里显示固件表登记的内容
  ASSERT_TRUE(restarted.firmware.find(missing.pkgId, &package));
  EXPECT_FALSE(package.usable);
}
