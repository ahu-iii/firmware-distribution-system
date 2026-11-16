#include "common/frame_codec.h"

#include <QtEndian>

namespace fwds {

namespace {
// 帧头各字段的偏移（协议 3.1 节）
constexpr int kOffVersion = 2;
constexpr int kOffType = 3;
constexpr int kOffSeq = 4;
constexpr int kOffLength = 12;
// 已消费的前缀超过这个大小就整理一次缓冲区，避免每取一帧都搬移内存
constexpr qsizetype kCompactThreshold = 64 * 1024;
}  // namespace

bool encodeFrame(quint8 type, quint64 seq, const QByteArray& body, QByteArray* out,
                 quint32 maxBody) {
  if (static_cast<quint64>(body.size()) > maxBody) return false;

  uchar header[kHeaderSize];
  header[0] = kMagic0;
  header[1] = kMagic1;
  header[kOffVersion] = kProtocolVersion;
  header[kOffType] = type;
  qToBigEndian<quint64>(seq, header + kOffSeq);
  qToBigEndian<quint32>(static_cast<quint32>(body.size()), header + kOffLength);

  out->append(reinterpret_cast<const char*>(header), kHeaderSize);
  out->append(body);
  return true;
}

FrameDecoder::FrameDecoder(quint32 maxBody) : maxBody_(maxBody) {}

void FrameDecoder::feed(const QByteArray& data) {
  if (error_ != ErrorCode::Ok) return;
  buffer_.append(data);
}

DecodeStatus FrameDecoder::next(Frame* out) {
  if (error_ != ErrorCode::Ok) return DecodeStatus::Error;

  // 第 1 步：不足一个帧头就等待
  if (buffered() < kHeaderSize) return DecodeStatus::NeedMore;

  // 第 2 步：只看帧头的 16 字节做检查。Length 在这里就判上限，
  // 此时还没有为 Body 分配任何内存，对端谎报长度占不到便宜。
  const uchar* h = reinterpret_cast<const uchar*>(buffer_.constData()) + pos_;
  ErrorCode headerError = ErrorCode::Ok;
  if (h[0] != kMagic0 || h[1] != kMagic1) {
    headerError = ErrorCode::BadMagic;
  } else if (h[kOffVersion] != kProtocolVersion) {
    headerError = ErrorCode::BadVersion;
  }
  const quint32 length = qFromBigEndian<quint32>(h + kOffLength);
  if (headerError == ErrorCode::Ok && length > maxBody_) {
    headerError = ErrorCode::FrameTooLarge;
  }
  if (headerError != ErrorCode::Ok) {
    error_ = headerError;
    buffer_.clear();
    pos_ = 0;
    return DecodeStatus::Error;
  }

  // 第 3 步：Body 没收齐就等待（半包）
  const qsizetype total = kHeaderSize + static_cast<qsizetype>(length);
  if (buffered() < total) return DecodeStatus::NeedMore;

  // 第 4 步：取出一帧。调用方循环调用 next() 即可处理粘包。
  out->type = h[kOffType];
  out->seq = qFromBigEndian<quint64>(h + kOffSeq);
  out->body = buffer_.mid(pos_ + kHeaderSize, length);
  pos_ += total;

  if (pos_ == buffer_.size()) {
    buffer_.clear();
    pos_ = 0;
  } else if (pos_ >= kCompactThreshold) {
    buffer_.remove(0, pos_);
    pos_ = 0;
  }
  return DecodeStatus::FrameReady;
}

}  // namespace fwds
