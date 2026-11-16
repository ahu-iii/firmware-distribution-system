// FrameCodec：FWDS 帧的编码和流式拆包（协议 3.1、3.2 节）。
// 纯内存操作，不碰 socket，可以单独做单元测试。
#pragma once

#include <QByteArray>

#include "common/protocol.h"

namespace fwds {

// 把一帧编码成字节串追加到 out。body 超过 maxBody 返回 false，out 不变。
bool encodeFrame(quint8 type, quint64 seq, const QByteArray& body, QByteArray* out,
                 quint32 maxBody = kMaxBodyLength);

enum class DecodeStatus {
  NeedMore,    // 数据不足一帧，等下次 feed
  FrameReady,  // 取出了一帧
  Error,       // 帧头非法，连接必须断开；之后一直返回 Error
};

// 流式拆包器：每条连接的每个接收方向一个。
// 用法：收到字节就 feed()，然后循环调用 next() 直到不是 FrameReady。
class FrameDecoder {
 public:
  explicit FrameDecoder(quint32 maxBody = kMaxBodyLength);

  // 追加从 socket 读到的字节。出错之后的数据直接丢弃。
  void feed(const QByteArray& data);

  // 尝试取出一帧，处理半包（NeedMore）和粘包（可连续返回 FrameReady）。
  DecodeStatus next(Frame* out);

  // 状态为 Error 时的具体原因：1001 / 1002 / 1003。
  ErrorCode error() const { return error_; }

  // 缓冲区里还没解析的字节数。
  qsizetype buffered() const { return buffer_.size() - pos_; }

 private:
  QByteArray buffer_;
  qsizetype pos_ = 0;  // buffer_ 中下一帧的起始位置
  quint32 maxBody_;
  ErrorCode error_ = ErrorCode::Ok;
};

}  // namespace fwds
