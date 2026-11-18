// ResumeStore：断点续传的落盘部分（设计第 3 节 ResumeManager，4.3、5.2 节）。
// 管理下载目录里的两个文件：
//   <pkg_id>.part        下载中的镜像。一开始就按镜像大小建好，每一片按自己的偏移写进去
//   <pkg_id>.state.json  断点记录：manifest 的哈希 + 已完成分片的位图
// 进度不只放在内存里：每完成 16 片落盘一次，断网、进程被杀、断电之后都能从断点接着下。
//
// 落盘顺序：先把 .part 刷到磁盘，再原子地写断点记录。这样断点记录里说“已完成”的分片，
// 数据一定已经在盘上。即使断点记录不可信（文件被改、磁盘出错），续传前 recheck() 还会把
// 标记为已完成的分片从 .part 里读出来重新算一遍哈希，不符的重新下载。
#pragma once

#include <QByteArray>
#include <QFile>
#include <QString>
#include <functional>

#include "client/storage/chunk_bitmap.h"
#include "common/manifest.h"

namespace fwds {

class ResumeStore {
 public:
  // downloadDir 是设备数据目录下的 download/，不存在时自动创建。
  // saveEveryChunks：每完成多少片把进度落盘一次。
  explicit ResumeStore(const QString& downloadDir, int saveEveryChunks = 16);
  ~ResumeStore();

  // 开始或继续下载 manifest 描述的固件。manifest 必须已经通过验签。
  //   - 有同一个包、同一份 manifest 的断点记录：载入位图，接着下；
  //   - 没有断点记录，或 manifest 哈希变了（固件已更换）：丢弃旧进度，从头开始。
  // 目录里其他包留下的文件一并删除（同一时间只下载一个包）。
  // 磁盘空间不够或文件无法创建时返回 false。“空间够”指可用空间不少于
  // “还没下载的部分 + 一整个镜像”：下载缓存要写满，校验通过后还要再写一份到非活动分区。
  bool open(const Manifest& manifest, const QByteArray& manifestRaw, QString* error);

  bool isOpen() const { return part_.isOpen(); }

  // 续传前重新校验：检查下标在 [from, from + maxChunks) 里、位图标记为已完成的分片，
  // 从 .part 读出来和 manifest 的分片哈希比对，不符的改回未完成。
  // 返回下一次该从哪一片接着查；返回值等于总片数表示全部查完。
  // 每次只查一小段，是为了让调用方能在两段之间回到事件循环，界面不会卡住。
  int recheck(int from, int maxChunks);

  // 写入一片。调用方必须已经用 chunkMatches() 校验过 data。
  // 每攒够 saveEveryChunks 片自动落盘一次。写失败（比如磁盘满）返回 false。
  bool writeChunk(int index, const QByteArray& data, QString* error);

  // 立刻落盘：.part 刷盘 + 原子写断点记录。断线、下载完成时调用。
  bool flush(QString* error);

  // 落盘并关闭文件，保留断点。
  void close();

  // 关闭并删除 .part 和断点记录（升级被取消、分片多次校验失败）。
  void discard();

  // 查询某个目录所在磁盘的可用字节数。默认用 QStorageInfo；单元测试换成固定值模拟磁盘快满。
  using FreeSpaceProbe = std::function<qint64(const QString& dir)>;
  void setFreeSpaceProbe(FreeSpaceProbe probe) { freeSpace_ = std::move(probe); }

  const ChunkBitmap& bitmap() const { return bitmap_; }
  QString partPath() const { return part_.fileName(); }
  QString statePath() const { return statePath_; }

 private:
  bool loadState();                  // 读断点记录，和当前 manifest 对得上才返回 true
  bool saveState(QString* error);    // 原子写断点记录
  void removeOtherPackages() const;  // 删除别的包留下的文件

  QString dir_;
  int saveEveryChunks_;
  Manifest manifest_;
  QByteArray manifestSha256_;  // manifest 原始字节的 SHA-256，用来判断“还是不是同一个固件”
  QFile part_;
  QString statePath_;
  ChunkBitmap bitmap_;
  int unsavedChunks_ = 0;      // 上次落盘之后又完成了几片
  FreeSpaceProbe freeSpace_;
};

}  // namespace fwds
