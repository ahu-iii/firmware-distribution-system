#include "client/storage/chunk_bitmap.h"

namespace fwds {

ChunkBitmap::ChunkBitmap(int chunkCount)
    : chunkCount_(qMax(0, chunkCount)), bits_((chunkCount_ + 7) / 8, '\0') {}

bool ChunkBitmap::test(int index) const {
  if (index < 0 || index >= chunkCount_) return false;
  return (static_cast<quint8>(bits_.at(index / 8)) >> (index % 8)) & 1;
}

void ChunkBitmap::set(int index) {
  if (index < 0 || index >= chunkCount_ || test(index)) return;
  bits_[index / 8] = static_cast<char>(static_cast<quint8>(bits_.at(index / 8)) | (1u << (index % 8)));
  ++doneCount_;
}

void ChunkBitmap::clear(int index) {
  if (!test(index)) return;
  bits_[index / 8] = static_cast<char>(static_cast<quint8>(bits_.at(index / 8)) & ~(1u << (index % 8)));
  --doneCount_;
}

int ChunkBitmap::firstMissing(int from) const {
  for (int index = qMax(0, from); index < chunkCount_; ++index) {
    if (!test(index)) return index;
  }
  return chunkCount_;
}

bool ChunkBitmap::fromBytes(const QByteArray& bytes, int chunkCount, ChunkBitmap* out) {
  ChunkBitmap bitmap(chunkCount);
  if (bytes.size() != bitmap.bits_.size()) return false;
  // 逐位搬过来并重新计数；doneCount_ 不从文件里读，免得和位图本身不一致
  for (int index = 0; index < bitmap.chunkCount_; ++index) {
    if ((static_cast<quint8>(bytes.at(index / 8)) >> (index % 8)) & 1) bitmap.set(index);
  }
  // 搬完之后两边必须一模一样；不一样说明最后一个字节里有超出片数的位被置了 1
  if (bitmap.bits_ != bytes) return false;
  *out = bitmap;
  return true;
}

}  // namespace fwds
