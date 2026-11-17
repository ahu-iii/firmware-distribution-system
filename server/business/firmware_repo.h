// FirmwareRepo：服务端的固件仓库（设计第 3 节）。
// 导入 .fwpkg 时服务端自己也完整检查一遍（验签、逐片哈希、整镜像哈希），不合格的包进不了仓库，
// 所以后面 ChunkService 从仓库里读出来发给设备的分片，都出自检查过的文件。
// 目前仓库只在内存里记“包 ID → 文件位置”；固件表入库和导入界面随灰度发布一步完成。
#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>

#include "common/firmware_package.h"

namespace fwds {

// 仓库里的一个固件包：通知设备和读分片需要的全部信息。
struct StoredPackage {
  Manifest manifest;        // 已验签的 manifest
  QByteArray manifestRaw;   // manifest 原始字节，UPDATE_NOTIFY 原样转发给设备
  QByteArray signature;     // FSK 签名，原样转发
  QString filePath;         // .fwpkg 文件
  qint64 imageOffset = 0;   // 镜像第一个字节在文件里的偏移
};

class FirmwareRepo {
 public:
  // verifier 里已装好 FSK 公钥，必须比 FirmwareRepo 活得久。
  explicit FirmwareRepo(const ManifestVerifier& verifier);

  // 导入一个 .fwpkg：整包检查通过才登记。失败时返回具体是哪一步不过，仓库不变。
  PackageCheck import(const QString& path, StoredPackage* out, QString* error);

  // 按包 ID 查找，找不到返回 false。
  bool find(const QString& pkgId, StoredPackage* out) const;

 private:
  const ManifestVerifier& verifier_;
  QHash<QString, StoredPackage> packages_;  // 包 ID → 包
};

}  // namespace fwds
