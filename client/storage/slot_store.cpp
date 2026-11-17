#include "client/storage/slot_store.h"

#include <QDir>
#include <QSaveFile>

#include "client/storage/file_sync.h"
#include "common/firmware_package.h"
#include "common/manifest.h"

namespace fwds {

namespace {

const QString kImageFile = QStringLiteral("firmware.bin");
const QString kManifestFile = QStringLiteral("manifest.json");
const QString kSignatureFile = QStringLiteral("manifest.sig");

// 读一个小文件：先看大小，为空或超过 maxSize 的不读。
bool readSmallFile(const QString& path, qint64 maxSize, QByteArray* out) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly) || file.size() < 1 || file.size() > maxSize) return false;
  *out = file.readAll();
  return out->size() == file.size();
}

// 原子写一个小文件（先写临时文件并刷盘，再改名）。
bool writeSmallFile(const QString& path, const QByteArray& data) {
  QSaveFile file(path);
  return file.open(QIODevice::WriteOnly) && file.write(data) == data.size() && file.commit();
}

}  // namespace

SlotStore::SlotStore(const QString& deviceDir) : deviceDir_(deviceDir) {}

QString SlotStore::bootConfigPath() const {
  return QDir(deviceDir_).filePath(QStringLiteral("boot.json"));
}

QString SlotStore::slotDir(const QString& slot) const {
  return QDir(deviceDir_).filePath(QStringLiteral("slot_") + slot);
}

QString SlotStore::imagePath(const QString& slot) const {
  return QDir(slotDir(slot)).filePath(kImageFile);
}

bool SlotStore::readManifest(const QString& slot, QByteArray* manifestRaw,
                             QByteArray* signature) const {
  const QDir dir(slotDir(slot));
  return readSmallFile(dir.filePath(kManifestFile), kMaxManifestSize, manifestRaw) &&
         readSmallFile(dir.filePath(kSignatureFile), kMaxPackageSignatureSize, signature);
}

bool SlotStore::hasImage(const QString& slot) const { return QFile::exists(imagePath(slot)); }

bool SlotWriter::begin(const QString& slotDir, const QString& sourcePath, qint64 sourceOffset,
                       qint64 imageSize, QString* error) {
  abort();
  slotDir_ = slotDir;
  imageSize_ = imageSize;
  written_ = 0;
  if (!QDir().mkpath(slotDir)) {
    *error = QStringLiteral("无法创建分区目录 %1").arg(slotDir);
    return false;
  }
  // 第一件事：让这个分区“不可启动”。旧 manifest 一删，Bootloader 就不会再认它
  const QDir dir(slotDir);
  QFile::remove(dir.filePath(kManifestFile));
  QFile::remove(dir.filePath(kSignatureFile));
  if (dir.exists(kManifestFile) || dir.exists(kSignatureFile)) {
    *error = QStringLiteral("无法清除分区 %1 里的旧 manifest").arg(slotDir);
    return false;
  }

  source_.setFileName(sourcePath);
  if (!source_.open(QIODevice::ReadOnly) || !source_.seek(sourceOffset)) {
    *error = QStringLiteral("无法读取 %1：%2").arg(sourcePath, source_.errorString());
    return false;
  }
  image_.setFileName(dir.filePath(kImageFile));
  if (!image_.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    *error = QStringLiteral("无法写入 %1：%2").arg(image_.fileName(), image_.errorString());
    return false;
  }
  return true;
}

bool SlotWriter::copySome(qint64 maxBytes, QString* error) {
  const qint64 want = qMin(maxBytes, imageSize_ - written_);
  const QByteArray data = source_.read(want);
  if (data.size() != want) {
    *error = QStringLiteral("源文件读不满（要 %1 字节，读到 %2 字节）").arg(want).arg(data.size());
    return false;
  }
  if (image_.write(data) != want) {
    *error = QStringLiteral("写入分区失败：%1").arg(image_.errorString());
    return false;
  }
  written_ += want;
  return true;
}

bool SlotWriter::finish(const QByteArray& manifestRaw, const QByteArray& signature, QString* error) {
  // 顺序不能反：镜像先刷盘，manifest 和签名后写
  if (!atEnd() || !syncToDisk(&image_)) {
    *error = QStringLiteral("固件镜像刷盘失败：%1").arg(image_.errorString());
    return false;
  }
  image_.close();
  source_.close();
  const QDir dir(slotDir_);
  if (!writeSmallFile(dir.filePath(kSignatureFile), signature) ||
      !writeSmallFile(dir.filePath(kManifestFile), manifestRaw)) {
    *error = QStringLiteral("无法写入分区 %1 的 manifest").arg(slotDir_);
    return false;
  }
  return true;
}

void SlotWriter::abort() {
  image_.close();
  source_.close();
}

}  // namespace fwds
