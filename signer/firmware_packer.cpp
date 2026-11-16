#include "signer/firmware_packer.h"

#include <QDateTime>
#include <QFile>
#include <QSaveFile>

#include "common/crypto/rand.h"
#include "common/crypto/rsa_pss.h"
#include "common/crypto/sha256.h"
#include "common/firmware_package.h"

namespace fwds {

QString newPackageId() {
  QByteArray id = randomBytes(16);
  // UUID 第 4 版的两处固定位：第 7 字节高 4 位是版本号 4，第 9 字节最高两位是 10
  id[6] = static_cast<char>((id[6] & 0x0F) | 0x40);
  id[8] = static_cast<char>((id[8] & 0x3F) | 0x80);
  const QString hex = QString::fromLatin1(id.toHex());
  // 按 8-4-4-4-12 分组
  return QStringLiteral("%1-%2-%3-%4-%5")
      .arg(hex.mid(0, 8), hex.mid(8, 4), hex.mid(12, 4), hex.mid(16, 4), hex.mid(20, 12));
}

bool buildManifest(QIODevice* image, const FirmwareInfo& info, Manifest* manifest, QString* error) {
  Manifest m;
  m.pkgId = newPackageId();
  m.deviceModel = info.deviceModel;
  m.version = info.version;
  m.securityVersion = info.securityVersion;
  m.buildTime = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
  m.releaseNote = info.releaseNote;

  Sha256 whole;  // 整镜像哈希，和分片哈希同时算
  while (true) {
    const QByteArray chunk = image->read(kChunkSize);
    if (chunk.isEmpty()) break;  // 读完了
    m.imageSize += chunk.size();
    if (m.imageSize > kMaxImageSize) {
      *error = QStringLiteral("镜像超过 %1 MB").arg(kMaxImageSize / (1024 * 1024));
      return false;
    }
    m.chunkSha256.append(sha256(chunk));
    whole.update(chunk);
  }
  m.chunkCount = static_cast<int>(m.chunkSha256.size());
  m.imageSha256 = whole.finish();

  // 空镜像、型号或版本号格式不对等问题在这里统一报出来
  if (!checkManifest(m, error)) return false;
  *manifest = m;
  return true;
}

bool signFirmware(const QString& imagePath, const FirmwareInfo& info, EVP_PKEY* fskPrivateKey,
                  const QString& outPath, Manifest* manifest, QString* error) {
  if (QFile::exists(outPath)) {
    *error = QStringLiteral("%1 已存在，拒绝覆盖").arg(outPath);
    return false;
  }
  QFile image(imagePath);
  if (!image.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取镜像 %1").arg(imagePath);
    return false;
  }

  // 第一遍读镜像：算哈希，生成 manifest
  Manifest m;
  if (!buildManifest(&image, info, &m, error)) return false;
  if (m.imageSize != image.size()) {
    *error = QStringLiteral("镜像没有读完整：%1").arg(imagePath);
    return false;
  }

  // 签名针对序列化后的原始字节；写进包里的也是这同一串字节
  const QByteArray manifestRaw = serializeManifest(m);
  if (manifestRaw.size() > kMaxManifestSize) {
    *error = QStringLiteral("manifest 超过 %1 KB").arg(kMaxManifestSize / 1024);
    return false;
  }
  QByteArray signature;
  if (!rsaPssSign(fskPrivateKey, manifestRaw, &signature, error)) return false;

  // QSaveFile 先写临时文件，commit() 时才改名成 outPath；中途任何一步失败都不会留下半个包
  QSaveFile out(outPath);
  const QByteArray header = buildPackageHeader(manifestRaw, signature, m.imageSize);
  if (!out.open(QIODevice::WriteOnly) || out.write(header) != header.size()) {
    *error = QStringLiteral("无法写入 %1").arg(outPath);
    return false;
  }

  // 第二遍读镜像：一边拷进包里一边重算整镜像哈希。
  // 如果两遍之间镜像文件被改过，写进包里的内容就和已经签名的 manifest 对不上，这里能发现。
  if (!image.seek(0)) {
    *error = QStringLiteral("无法读取镜像 %1").arg(imagePath);
    return false;
  }
  Sha256 copied;
  while (true) {
    const QByteArray chunk = image.read(kChunkSize);
    if (chunk.isEmpty()) break;
    copied.update(chunk);
    if (out.write(chunk) != chunk.size()) {
      *error = QStringLiteral("无法写入 %1").arg(outPath);
      return false;
    }
  }
  if (copied.finish() != m.imageSha256) {
    *error = QStringLiteral("打包过程中镜像文件发生了变化，已放弃");
    return false;  // out 析构时自动丢弃临时文件
  }
  if (!out.commit()) {
    *error = QStringLiteral("无法写入 %1").arg(outPath);
    return false;
  }
  *manifest = m;
  return true;
}

}  // namespace fwds
