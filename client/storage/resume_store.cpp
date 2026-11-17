#include "client/storage/resume_store.h"

#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

#include "client/storage/file_sync.h"
#include "common/crypto/sha256.h"
#include "common/log.h"
#include "common/security/manifest_verifier.h"

namespace fwds {

ResumeStore::ResumeStore(const QString& downloadDir, int saveEveryChunks)
    : dir_(downloadDir), saveEveryChunks_(qMax(1, saveEveryChunks)) {}

ResumeStore::~ResumeStore() { close(); }

bool ResumeStore::open(const Manifest& manifest, const QByteArray& manifestRaw, QString* error) {
  close();
  if (!QDir().mkpath(dir_)) {
    *error = QStringLiteral("无法创建下载目录 %1").arg(dir_);
    return false;
  }

  manifest_ = manifest;
  manifestSha256_ = sha256(manifestRaw);
  // 文件名用包 ID 拼。包 ID 的字符集在 manifest 检查时已经卡死为小写 UUID，不会带路径分隔符
  const QString base = QDir(dir_).filePath(manifest.pkgId);
  part_.setFileName(base + QStringLiteral(".part"));
  statePath_ = base + QStringLiteral(".state.json");
  removeOtherPackages();

  const bool resumed = loadState();
  if (!resumed) {
    // 没有可用的断点：丢弃旧文件，位图清零
    QFile::remove(part_.fileName());
    QFile::remove(statePath_);
    bitmap_ = ChunkBitmap(manifest.chunkCount);
  }

  if (!part_.open(QIODevice::ReadWrite)) {
    *error = QStringLiteral("无法打开 %1：%2").arg(part_.fileName(), part_.errorString());
    return false;
  }
  // 一开始就把文件撑到镜像大小：空间不够在这里就能发现，之后每一片按偏移写入
  if (part_.size() != manifest.imageSize && !part_.resize(manifest.imageSize)) {
    *error = QStringLiteral("无法为下载文件预留 %1 字节").arg(manifest.imageSize);
    part_.close();
    return false;
  }
  unsavedChunks_ = 0;
  if (!resumed && !saveState(error)) {
    part_.close();
    return false;
  }
  qCInfo(lcApp).noquote() << (resumed ? "resume download" : "new download") << manifest.pkgId
                          << "chunks done" << bitmap_.doneCount() << "/" << bitmap_.size();
  return true;
}

int ResumeStore::recheck(int from, int maxChunks) {
  const int end = qMin(manifest_.chunkCount, from + maxChunks);
  for (int index = from; index < end; ++index) {
    if (!bitmap_.test(index)) continue;
    const qint64 offset = static_cast<qint64>(index) * manifest_.chunkSize;
    const bool readable = part_.seek(offset);
    const QByteArray data = readable ? part_.read(manifest_.chunkLength(index)) : QByteArray();
    if (!chunkMatches(manifest_, index, data)) {
      // 断点记录说这一片下完了，但盘上的内容对不上：改回未完成，等会儿重新下载
      qCWarning(lcSecurity) << "cached chunk" << index << "does not match manifest, will download again";
      bitmap_.clear(index);
    }
  }
  return end;
}

bool ResumeStore::writeChunk(int index, const QByteArray& data, QString* error) {
  const qint64 offset = static_cast<qint64>(index) * manifest_.chunkSize;
  if (!part_.isOpen() || !part_.seek(offset) || part_.write(data) != data.size()) {
    *error = QStringLiteral("写入分片 %1 失败：%2").arg(index).arg(part_.errorString());
    return false;
  }
  bitmap_.set(index);
  ++unsavedChunks_;
  if (unsavedChunks_ >= saveEveryChunks_) return flush(error);
  return true;
}

bool ResumeStore::flush(QString* error) {
  if (!part_.isOpen()) return true;
  // 顺序不能反：先让分片数据落盘，再更新断点记录
  if (!syncToDisk(&part_)) {
    *error = QStringLiteral("下载文件刷盘失败：%1").arg(part_.errorString());
    return false;
  }
  if (!saveState(error)) return false;
  unsavedChunks_ = 0;
  return true;
}

void ResumeStore::close() {
  if (!part_.isOpen()) return;
  QString error;
  if (!flush(&error)) qCWarning(lcApp).noquote() << "cannot save download progress:" << error;
  part_.close();
}

void ResumeStore::discard() {
  part_.close();
  if (!part_.fileName().isEmpty()) QFile::remove(part_.fileName());
  if (!statePath_.isEmpty()) QFile::remove(statePath_);
  bitmap_ = ChunkBitmap(manifest_.chunkCount);
  unsavedChunks_ = 0;
}

bool ResumeStore::loadState() {
  QFile file(statePath_);
  if (!file.open(QIODevice::ReadOnly)) return false;
  // 断点记录很小（256 MB 的镜像也只有几百字节位图），超过 64 KB 一定不是我们写的
  const QByteArray raw = file.read(64 * 1024);
  const QJsonObject obj = QJsonDocument::fromJson(raw).object();

  // manifest 哈希变了说明固件已经更换，旧进度不能用
  if (obj.value(QStringLiteral("pkg_id")).toString() != manifest_.pkgId ||
      obj.value(QStringLiteral("manifest_sha256")).toString() !=
          QString::fromLatin1(manifestSha256_.toHex()) ||
      obj.value(QStringLiteral("chunk_count")).toInt(-1) != manifest_.chunkCount) {
    return false;
  }
  const QByteArray bits =
      QByteArray::fromBase64(obj.value(QStringLiteral("bitmap")).toString().toLatin1());
  ChunkBitmap bitmap;
  if (!ChunkBitmap::fromBytes(bits, manifest_.chunkCount, &bitmap)) return false;
  // .part 不在了，位图就没有意义
  if (!QFile::exists(part_.fileName())) return false;
  bitmap_ = bitmap;
  return true;
}

bool ResumeStore::saveState(QString* error) {
  QJsonObject obj;
  obj.insert(QStringLiteral("pkg_id"), manifest_.pkgId);
  obj.insert(QStringLiteral("manifest_sha256"), QString::fromLatin1(manifestSha256_.toHex()));
  obj.insert(QStringLiteral("chunk_count"), manifest_.chunkCount);
  obj.insert(QStringLiteral("bitmap"), QString::fromLatin1(bitmap_.toBytes().toBase64()));

  // QSaveFile：先写临时文件并刷盘，commit() 时改名覆盖旧文件。
  // 写到一半断电，留下的还是完整的旧记录，不会出现半截的 JSON
  QSaveFile file(statePath_);
  if (!file.open(QIODevice::WriteOnly) ||
      file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact)) < 0 || !file.commit()) {
    *error = QStringLiteral("无法保存断点记录 %1：%2").arg(statePath_, file.errorString());
    return false;
  }
  return true;
}

void ResumeStore::removeOtherPackages() const {
  QDir dir(dir_);
  const QStringList names = dir.entryList(
      {QStringLiteral("*.part"), QStringLiteral("*.state.json")}, QDir::Files);
  for (const QString& name : names) {
    // 文件名是 "<pkg_id>.part" 或 "<pkg_id>.state.json"，第一个点之前就是包 ID
    if (name.section(QLatin1Char('.'), 0, 0) != manifest_.pkgId) dir.remove(name);
  }
}

}  // namespace fwds
