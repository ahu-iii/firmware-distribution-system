// ChunkBitmap：断点位图（设计 4.3 节）。每个分片占 1 比特，1 表示这一片已经下载并校验通过。
// 用位图而不是“已下载到第几片”的一个数，是因为分片可能不按顺序完成：
// 中间某一片哈希不符要重下时，它后面的分片可能已经好了。
#pragma once

#include <QByteArray>

namespace fwds {

class ChunkBitmap {
 public:
  // chunkCount 片，全部未完成。
  explicit ChunkBitmap(int chunkCount = 0);

  int size() const { return chunkCount_; }
  bool test(int index) const;   // 第 index 片是否已完成；下标越界返回 false
  void set(int index);          // 标记为已完成
  void clear(int index);        // 标记为未完成（续传前重新校验发现这一片坏了）

  int doneCount() const { return doneCount_; }
  bool isComplete() const { return doneCount_ == chunkCount_; }

  // 从 from 开始的第一个未完成分片；后面都完成了返回 size()。
  int firstMissing(int from = 0) const;

  // 位图的字节形式：第 i 片对应第 i / 8 个字节的第 i % 8 位（最低位是第 0 位）。
  QByteArray toBytes() const { return bits_; }

  // 从字节恢复。长度必须正好是 ⌈chunkCount / 8⌉，最后一个字节里多出来的位必须是 0，
  // 否则说明断点文件和这个固件对不上，返回 false。
  static bool fromBytes(const QByteArray& bytes, int chunkCount, ChunkBitmap* out);

 private:
  int chunkCount_ = 0;
  int doneCount_ = 0;
  QByteArray bits_;
};

}  // namespace fwds
