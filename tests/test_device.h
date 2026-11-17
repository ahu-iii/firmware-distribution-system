// 设备端（A/B 分区、Bootloader、Updater）测试共用的材料：
// 带模拟镜像头的签名固件，以及直接往分区目录里“烧”固件的办法。
#pragma once

#include <QDir>
#include <QFile>

#include "client/storage/boot_config.h"
#include "client/storage/slot_store.h"
#include "common/firmware_image.h"
#include "common/update_messages.h"
#include "test_fsk.h"

namespace fwds_test {

inline const QString kTestModel = QStringLiteral("PLC-X200");

inline void writeFile(const QString& path, const QByteArray& data) {
  QDir().mkpath(QFileInfo(path).absolutePath());
  QFile file(path);
  file.open(QIODevice::WriteOnly | QIODevice::Truncate);
  file.write(data);
}

inline QByteArray readFile(const QString& path) {
  QFile file(path);
  return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

// 一份签好名的模拟固件：镜像（37 字节头 + 随机载荷）、manifest 原始字节、签名。
struct DeviceFirmware {
  DeviceFirmware(const QString& version, int securityVersion, int size = 3 * fwds::kChunkSize + 100,
                 bool selfTestFails = false, const QString& model = kTestModel) {
    fwds::ImageHeader header;
    header.model = model;
    header.version = version;
    header.selfTestFails = selfTestFails;
    image = fwds::buildImageHeader(header);
    image += fwds::randomBytes(size - static_cast<int>(image.size()));

    fwds::FirmwareInfo info;
    info.deviceModel = model;
    info.version = version;
    info.securityVersion = securityVersion;
    manifest = manifestFor(image, info);
    raw = fwds::serializeManifest(manifest);
    signature = signWith(sharedFsk(), raw);
  }

  QByteArray chunk(int index) const { return image.mid(index * fwds::kChunkSize, fwds::kChunkSize); }

  QByteArray notifyBody(const QString& deviceId = QStringLiteral("DEV-001")) const {
    fwds::UpdateNotify n;
    n.deviceId = deviceId;
    n.releaseId = 12;
    n.pkgId = manifest.pkgId;
    n.manifestRaw = raw;
    n.signature = signature;
    return fwds::encodeUpdateNotify(n);
  }

  // 把这份固件直接放进设备目录的某个分区（相当于产线烧录，不经过升级流程）。
  void installTo(const QString& deviceDir, const QString& slot) const {
    const QDir dir(fwds::SlotStore(deviceDir).slotDir(slot));
    writeFile(dir.filePath(QStringLiteral("firmware.bin")), image);
    writeFile(dir.filePath(QStringLiteral("manifest.json")), raw);
    writeFile(dir.filePath(QStringLiteral("manifest.sig")), signature);
  }

  QByteArray image;
  fwds::Manifest manifest;
  QByteArray raw;
  QByteArray signature;
};

inline void writeBootConfig(const QString& deviceDir, const QString& active, const QString& pending,
                            int attempts, int minSecurityVersion) {
  fwds::BootConfig config;
  config.active = active;
  config.pending = pending;
  config.bootAttempts = attempts;
  config.minSecurityVersion = minSecurityVersion;
  QString error;
  QDir().mkpath(deviceDir);
  fwds::saveBootConfig(fwds::SlotStore(deviceDir).bootConfigPath(), config, &error);
}

inline fwds::BootConfig readBootConfig(const QString& deviceDir) {
  fwds::BootConfig config;
  fwds::loadBootConfig(fwds::SlotStore(deviceDir).bootConfigPath(), &config);
  return config;
}

}  // namespace fwds_test
