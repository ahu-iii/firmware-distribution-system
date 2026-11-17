// FirmwareRepo：服务端的固件库（设计第 3 节、5.1 节 FIRMWARE 表、12.1 节）。
//   导入    把 .fwpkg 复制进固件库目录，对“库里的这份副本”做整包检查
//           （容器结构 → manifest 验签 → 字段检查 → 逐片哈希 → 整镜像哈希），通过才登记进固件表；
//           任何一步不过，副本删除、库不变。检查的是副本而不是原文件：
//           之后发给设备的每一片都从副本里读，检查过的和发出去的是同一份字节
//   启动    按固件表把每个包重新检查一遍。文件丢了或者被动过的包标记为“不可用”，
//           留在列表里给维护员看，但不能下发
//   查询    固件库页面列出全部固件；发布模块按包 ID 取出要下发的包
// 导入是管理操作（只有维护员能做），所以 import() 是私有的，只对 AdminService 开放。
#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

#include "common/firmware_package.h"
#include "server/storage/database.h"

namespace fwds {

// 固件库里的一个固件包：通知设备和读分片需要的全部信息，加上入库记录。
struct StoredPackage {
  Manifest manifest;        // 已验签的 manifest
  QByteArray manifestRaw;   // manifest 原始字节，UPDATE_NOTIFY 原样转发给设备
  QByteArray signature;     // FSK 签名，原样转发
  QString filePath;         // 固件库目录里的 .fwpkg 文件
  qint64 imageOffset = 0;   // 镜像第一个字节在文件里的偏移
  QString importedBy;       // 导入它的维护员账号
  QDateTime importedAt;     // 导入时间（UTC）
  // 启动时重新检查没通过的包：usable 为 false，problem 说明原因。这样的包不能下发。
  bool usable = true;
  QString problem;
};

class FirmwareRepo : public QObject {
  Q_OBJECT
 public:
  // verifier 里已装好 FSK 公钥，必须比 FirmwareRepo 活得久。libraryDir 来自配置 [server] firmware_dir。
  FirmwareRepo(Database* db, const ManifestVerifier& verifier, const QString& libraryDir,
               QObject* parent = nullptr);

  // 服务端启动时调用：建好固件库目录，读固件表，逐个重新检查。
  bool load(QString* error);

  // 全部固件（含不可用的），按导入时间从新到旧。
  QList<StoredPackage> packages() const;
  // 按包 ID 查找，找不到返回 false。
  bool find(const QString& pkgId, StoredPackage* out) const;

  // 验签用的 FSK 公钥指纹，界面显示给维护员核对。
  QString fskFingerprint() const { return verifier_.publicKeyFingerprint(); }

 signals:
  void changed();

 private:
  friend class AdminService;  // import() 只能经 AdminService 调用（先过权限检查）

  // 导入一个 .fwpkg。失败时返回具体是哪一步不过，error 是可以显示给用户的说明，固件库不变。
  PackageCheck import(const QString& sourcePath, const QString& importedBy, StoredPackage* out,
                      QString* error);

  // 整包检查固件库目录里的一个文件，通过后填好 out 里除入库记录以外的字段。
  PackageCheck checkFile(const QString& path, StoredPackage* out, QString* error) const;
  bool insertRow(const StoredPackage& package, QString* error);

  Database* db_;
  const ManifestVerifier& verifier_;
  QString libraryDir_;
  QMap<QString, StoredPackage> packages_;  // 包 ID → 包
};

}  // namespace fwds
