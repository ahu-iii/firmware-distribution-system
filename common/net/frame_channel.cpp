#include "common/net/frame_channel.h"

#include <QJsonDocument>
#include <QTimer>

namespace fwds {

namespace {
constexpr qint64 kReadChunk = 64 * 1024;  // 每次从 socket 取出的最大字节数
constexpr int kCloseLingerMs = 2000;      // 关闭时等对端收完 ERROR 的最长时间
}  // namespace

FrameChannel::FrameChannel(QAbstractSocket* socket, quint32 maxBody, QObject* parent)
    : QObject(parent), socket_(socket), decoder_(maxBody), maxBody_(maxBody) {
  // 限制 socket 的接收缓冲：对端发得再快，内存里最多积压两帧左右
  socket_->setReadBufferSize(2 * (static_cast<qint64>(maxBody) + kHeaderSize));
  connect(socket_, &QAbstractSocket::readyRead, this, &FrameChannel::onReadyRead);
  // 握手期间可能已经有数据到达，补读一次
  if (socket_->bytesAvailable() > 0) {
    QMetaObject::invokeMethod(this, &FrameChannel::onReadyRead, Qt::QueuedConnection);
  }
}

bool FrameChannel::send(MsgType type, const QByteArray& body) {
  if (closed_ || socket_->state() != QAbstractSocket::ConnectedState) return false;
  QByteArray wire;
  if (!encodeFrame(static_cast<quint8>(type), sendSeq_ + 1, body, &wire, maxBody_)) return false;
  ++sendSeq_;
  // write() 只是放进 Qt 的发送缓冲，由事件循环在 socket 可写时发出，不会阻塞
  return socket_->write(wire) == wire.size();
}

bool FrameChannel::sendJson(MsgType type, const QJsonObject& body) {
  return send(type, QJsonDocument(body).toJson(QJsonDocument::Compact));
}

bool FrameChannel::sendError(ErrorCode code, const QString& message) {
  QJsonObject body;
  body.insert(QStringLiteral("code"), static_cast<int>(code));
  body.insert(QStringLiteral("message"),
              message.isEmpty() ? QString::fromLatin1(errorName(code)) : message);
  return sendJson(MsgType::Error, body);
}

void FrameChannel::fail(ErrorCode code, const QString& message) {
  if (closed_) return;
  sendError(code, message);
  closeGracefully();
}

void FrameChannel::closeGracefully() {
  if (closed_) return;
  closed_ = true;
  // disconnectFromHost 会先把发送缓冲里的数据发完再关闭
  socket_->disconnectFromHost();
  // 对端一直不收数据时不能无限等，超时强制断开
  QAbstractSocket* s = socket_;
  QTimer::singleShot(kCloseLingerMs, s, [s]() {
    if (s->state() != QAbstractSocket::UnconnectedState) s->abort();
  });
}

void FrameChannel::onReadyRead() {
  while (!closed_ && socket_->bytesAvailable() > 0) {
    decoder_.feed(socket_->read(kReadChunk));

    Frame frame;
    DecodeStatus status = DecodeStatus::NeedMore;
    while (!closed_ && (status = decoder_.next(&frame)) == DecodeStatus::FrameReady) {
      // 序号必须连续，从 1 开始（协议 3.3 节）
      if (frame.seq != recvSeq_ + 1) {
        const QString msg = QStringLiteral("sequence error: expected %1, got %2")
                                .arg(recvSeq_ + 1)
                                .arg(frame.seq);
        fail(ErrorCode::SeqError, QStringLiteral("sequence error"));
        emit protocolError(ErrorCode::SeqError, msg);
        return;
      }
      recvSeq_ = frame.seq;
      emit frameReceived(frame);
    }

    if (!closed_ && status == DecodeStatus::Error) {
      const ErrorCode code = decoder_.error();
      fail(code);
      emit protocolError(code, QString::fromLatin1(errorName(code)));
      return;
    }
  }
}

}  // namespace fwds
