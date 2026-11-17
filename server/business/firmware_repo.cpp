#include "server/business/firmware_repo.h"

#include <QFile>

#include "common/log.h"

namespace fwds {

FirmwareRepo::FirmwareRepo(const ManifestVerifier& verifier) : verifier_(verifier) {}

PackageCheck FirmwareRepo::import(const QString& path, StoredPackage* out, QString* error) {
  // 整包检查：容器结构 → manifest 验签 → 解析 → 镜像长度 → 逐片哈希 → 整镜像哈希
  StoredPackage package;
  const PackageCheck check = verifyPackageFile(path, verifier_, &package.manifest, error);
  if (check != PackageCheck::Ok) {
    qCCritical(lcSecurity).noquote() << "firmware import rejected:" << path << *error;
    return check;
  }

  // 检查通过后再取一次容器头，记下 manifest 原始字节、签名和镜像在文件里的位置
  QFile file(path);
  PackageHeader header;
  if (!file.open(QIODevice::ReadOnly) || !readPackageHeader(&file, &header, error)) {
    return PackageCheck::BadContainer;
  }
  package.manifestRaw = header.manifestRaw;
  package.signature = header.signature;
  package.filePath = path;
  package.imageOffset = header.imageOffset;

  packages_.insert(package.manifest.pkgId, package);
  qCInfo(lcApp).noquote() << "firmware imported:" << package.manifest.pkgId
                          << package.manifest.deviceModel << package.manifest.version;
  *out = package;
  return PackageCheck::Ok;
}

bool FirmwareRepo::find(const QString& pkgId, StoredPackage* out) const {
  const auto it = packages_.constFind(pkgId);
  if (it == packages_.constEnd()) return false;
  *out = it.value();
  return true;
}

}  // namespace fwds
