#include "client/business/provisioner.h"

#include <QDir>
#include <QFile>

#include "client/business/bootloader.h"
#include "client/storage/boot_config.h"
#include "client/storage/slot_store.h"
#include "common/firmware_package.h"

namespace fwds {

bool provisionDevice(const QString& deviceDir, const QString& packagePath,
                     const ManifestVerifier& verifier, const QString& deviceModel, QString* error) {
  const SlotStore store(deviceDir);
  const QString factorySlot = QStringLiteral("a");
  if (QFile::exists(store.bootConfigPath()) || store.hasImage(factorySlot) ||
      store.hasImage(otherSlot(factorySlot))) {
    *error = QStringLiteral("设备目录 %1 里已经有固件，出厂写入只用于空设备").arg(deviceDir);
    return false;
  }

  // ① 整包检查：容器结构 → 验签 → 解析 manifest → 逐片哈希 → 整镜像哈希
  Manifest manifest;
  if (verifyPackageFile(packagePath, verifier, &manifest, error) != PackageCheck::Ok) return false;
  if (manifest.deviceModel != deviceModel) {
    *error = QStringLiteral("固件适用型号 %1，本设备型号 %2").arg(manifest.deviceModel, deviceModel);
    return false;
  }

  // ② 找到镜像在包文件里的位置，拷进分区 a
  QFile package(packagePath);
  PackageHeader header;
  if (!package.open(QIODevice::ReadOnly) || !readPackageHeader(&package, &header, error)) {
    return false;
  }
  package.close();
  if (!QDir().mkpath(deviceDir)) {
    *error = QStringLiteral("无法创建设备目录 %1").arg(deviceDir);
    return false;
  }
  SlotWriter writer;
  if (!writer.begin(store.slotDir(factorySlot), packagePath, header.imageOffset, manifest.imageSize,
                    error)) {
    return false;
  }
  while (!writer.atEnd()) {
    if (!writer.copySome(1024 * 1024, error)) return false;
  }
  if (!writer.finish(header.manifestRaw, header.signature, error)) return false;

  // ③ 建立 boot.json：从分区 a 启动，最小安全版本号就是出厂固件的安全版本号
  BootConfig config;
  config.active = factorySlot;
  config.minSecurityVersion = manifest.securityVersion;
  if (!saveBootConfig(store.bootConfigPath(), config, error)) return false;

  // ④ 用 Bootloader 的眼光再看一遍：写进去的固件确实能启动、能过自检
  const Bootloader bootloader(deviceDir, verifier, deviceModel);
  Manifest installed;
  return bootloader.checkSlot(factorySlot, config.minSecurityVersion, true, &installed, error) ==
         ErrorCode::Ok;
}

}  // namespace fwds
