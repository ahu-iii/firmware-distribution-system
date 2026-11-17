#include "server/business/firmware_repo.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>
#include <algorithm>

#include "common/log.h"

namespace fwds {

namespace {

// 一个合法的 .fwpkg 最大能有多大：镜像上限 + manifest 上限 + 签名上限 + 容器里的几个定长字段。
// 比这还大的文件肯定不是合法的包，不用复制进固件库再检查。
constexpr qint64 kMaxPackageFileSize = kMaxImageSize + kMaxManifestSize + kMaxPackageSignatureSize + 64;

QString sqlError(const QSqlQuery& query) {
  return QStringLiteral("数据库操作失败：%1").arg(query.lastError().text());
}

}  // namespace

FirmwareRepo::FirmwareRepo(Database* db, const ManifestVerifier& verifier,
                           const QString& libraryDir, QObject* parent)
    : QObject(parent), db_(db), verifier_(verifier), libraryDir_(libraryDir) {}

bool FirmwareRepo::load(QString* error) {
  if (!QDir().mkpath(libraryDir_)) {
    *error = QStringLiteral("无法创建固件库目录：%1").arg(libraryDir_);
    return false;
  }
  QSqlQuery query(db_->handle());
  if (!query.exec(QStringLiteral(
          "SELECT pkg_id, model, version, security_version, image_size, image_sha256, file_path,"
          " imported_by, imported_at FROM firmware"))) {
    *error = sqlError(query);
    return false;
  }
  packages_.clear();
  while (query.next()) {
    const QString pkgId = query.value(0).toString();
    StoredPackage package;
    // 文件一律到固件库目录里找：只取登记的文件名部分，表里的内容不能把读取引到别的目录去
    const QString path = QDir(libraryDir_).filePath(QFileInfo(query.value(6).toString()).fileName());
    QString problem;
    const PackageCheck check = checkFile(path, &package, &problem);
    if (check != PackageCheck::Ok) {
      package.usable = false;
      package.problem = problem;
    } else if (package.manifest.pkgId != pkgId ||
               package.manifest.imageSha256.toHex() != query.value(5).toString().toLatin1()) {
      // 文件本身是一个合法的包，但不是入库时登记的那一个（文件被换成了另一个包）
      package.usable = false;
      package.problem = QStringLiteral("文件内容与入库时登记的包不一致");
    }
    if (!package.usable) {
      // 不可用的包没有可信的 manifest，列表里显示固件表登记的内容
      package.manifest = Manifest();
      package.manifest.pkgId = pkgId;
      package.manifest.deviceModel = query.value(1).toString();
      package.manifest.version = query.value(2).toString();
      package.manifest.securityVersion = query.value(3).toInt();
      package.manifest.imageSize = query.value(4).toLongLong();
      package.manifest.imageSha256 = QByteArray::fromHex(query.value(5).toString().toLatin1());
      package.filePath = path;
      qCCritical(lcSecurity).noquote() << "firmware" << pkgId << "failed the startup check:"
                                       << package.problem;
    }
    package.importedBy = query.value(7).toString();
    package.importedAt = QDateTime::fromString(query.value(8).toString(), Qt::ISODate);
    packages_.insert(pkgId, package);
  }
  qCInfo(lcApp) << "firmware library loaded," << packages_.size() << "package(s)";
  emit changed();
  return true;
}

QList<StoredPackage> FirmwareRepo::packages() const {
  QList<StoredPackage> list = packages_.values();
  std::sort(list.begin(), list.end(), [](const StoredPackage& a, const StoredPackage& b) {
    return a.importedAt > b.importedAt;
  });
  return list;
}

bool FirmwareRepo::find(const QString& pkgId, StoredPackage* out) const {
  const auto it = packages_.constFind(pkgId);
  if (it == packages_.constEnd()) return false;
  if (out) *out = it.value();
  return true;
}

PackageCheck FirmwareRepo::checkFile(const QString& path, StoredPackage* out,
                                     QString* error) const {
  // 整包检查：容器结构 → manifest 验签 → 解析 → 镜像长度 → 逐片哈希 → 整镜像哈希
  const PackageCheck check = verifyPackageFile(path, verifier_, &out->manifest, error);
  if (check != PackageCheck::Ok) return check;

  // 检查通过后再取一次容器头，记下 manifest 原始字节、签名和镜像在文件里的位置
  QFile file(path);
  PackageHeader header;
  if (!file.open(QIODevice::ReadOnly) || !readPackageHeader(&file, &header, error)) {
    return PackageCheck::BadContainer;
  }
  out->manifestRaw = header.manifestRaw;
  out->signature = header.signature;
  out->filePath = path;
  out->imageOffset = header.imageOffset;
  return PackageCheck::Ok;
}

PackageCheck FirmwareRepo::import(const QString& sourcePath, const QString& importedBy,
                                  StoredPackage* out, QString* error) {
  // ① 先看大小：超过合法包的最大尺寸就不往固件库里复制
  const QFileInfo source(sourcePath);
  if (!source.isFile() || source.size() > kMaxPackageFileSize) {
    *error = QStringLiteral("文件不存在，或者超过了固件包的大小上限");
    return PackageCheck::BadContainer;
  }

  // ② 复制进固件库目录，先用一个随机的临时名字（包 ID 要等验签通过才可信）
  const QDir library(libraryDir_);
  const QString tempPath = library.filePath(
      QStringLiteral("import-%1.tmp").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
  if (!QFile::copy(sourcePath, tempPath)) {
    *error = QStringLiteral("无法把文件复制到固件库目录 %1").arg(libraryDir_);
    return PackageCheck::BadContainer;
  }
  // 固件库里的文件只让运行账户读写
  QFile::setPermissions(tempPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);

  // ③ 整包检查这份副本。不通过：删掉副本，记安全日志
  StoredPackage package;
  const PackageCheck check = checkFile(tempPath, &package, error);
  if (check != PackageCheck::Ok) {
    QFile::remove(tempPath);
    qCCritical(lcSecurity).noquote() << "firmware import rejected:" << source.fileName() << *error;
    return check;
  }

  // ④ 同一个包不重复入库
  const QString pkgId = package.manifest.pkgId;
  if (packages_.contains(pkgId)) {
    QFile::remove(tempPath);
    *error = QStringLiteral("这个固件包已经在固件库里了（%1 %2）")
                 .arg(package.manifest.deviceModel, package.manifest.version);
    return PackageCheck::BadManifest;
  }

  // ⑤ 改成正式的名字“包 ID.fwpkg”。包 ID 的格式在 manifest 检查里卡死为小写 UUID，可以直接当文件名
  const QString finalPath = library.filePath(pkgId + QStringLiteral(".fwpkg"));
  QFile::remove(finalPath);  // 固件表里没有它，说明是以前留下的无主文件
  if (!QFile::rename(tempPath, finalPath)) {
    QFile::remove(tempPath);
    *error = QStringLiteral("无法在固件库目录里保存 %1").arg(QFileInfo(finalPath).fileName());
    return PackageCheck::BadContainer;
  }
  package.filePath = finalPath;
  package.importedBy = importedBy;
  package.importedAt = QDateTime::currentDateTimeUtc();

  // ⑥ 登记进固件表。写库失败就把文件也撤掉，库和目录保持一致
  if (!insertRow(package, error)) {
    QFile::remove(finalPath);
    return PackageCheck::BadContainer;
  }
  packages_.insert(pkgId, package);
  qCInfo(lcApp).noquote() << "firmware imported:" << pkgId << package.manifest.deviceModel
                          << package.manifest.version;
  *out = package;
  emit changed();
  return PackageCheck::Ok;
}

bool FirmwareRepo::insertRow(const StoredPackage& package, QString* error) {
  const Manifest& m = package.manifest;
  QSqlQuery query(db_->handle());
  query.prepare(QStringLiteral(
      "INSERT INTO firmware (pkg_id, model, version, security_version, image_size, image_sha256,"
      " file_path, imported_by, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"));
  query.addBindValue(m.pkgId);
  query.addBindValue(m.deviceModel);
  query.addBindValue(m.version);
  query.addBindValue(m.securityVersion);
  query.addBindValue(m.imageSize);
  query.addBindValue(QString::fromLatin1(m.imageSha256.toHex()));
  query.addBindValue(QFileInfo(package.filePath).fileName());
  query.addBindValue(package.importedBy);
  query.addBindValue(package.importedAt.toString(Qt::ISODate));
  if (!query.exec()) {
    *error = sqlError(query);
    return false;
  }
  return true;
}

}  // namespace fwds
