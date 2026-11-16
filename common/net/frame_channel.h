// FrameChannel：一条已建立的连接上的 FWDS 帧收发。
// 负责：非阻塞读、拆包、接收序号检查、发送序号分配、出错时发 ERROR 并断开。
// 不理解消息体内容。每条连接新建一个对象，所以重连后序号自然从 1 开始。
#pragma once

#include <QAbstractSocket>
#include <QJsonObject>
#include <QObject>

#include "common/frame_codec.h"

namespace fwds {

class FrameChannel : public QObject {
  Q_OBJECT
 public:
  // socket 由调用方持有，必须比本对象活得久。
  FrameChannel(QAbstractSocket* socket, quint32 maxBody, QObject* parent = nullptr);

  // 发送一帧，序号自动加 1。body 超长或连接已关闭时返回 false。
  bool send(MsgType type, const QByteArray& body);
  bool sendJson(MsgType type, const QJsonObject& body);

  // 发送 ERROR 帧但不关闭连接（3xxx 和 1005）。
  bool sendError(ErrorCode code, const QString& message = QString());

  // 发送 ERROR 帧后关闭连接（1xxx、2xxx）。之后收到的数据全部丢弃。
  void fail(ErrorCode code, const QString& message = QString());

  // 把已排队的数据发完后关闭连接。
  void closeGracefully();

  bool isClosed() const { return closed_; }
  quint64 framesSent() const { return sendSeq_; }
  quint64 framesReceived() const { return recvSeq_; }

 signals:
  // 收到一帧，帧头和序号已通过检查。
  void frameReceived(const fwds::Frame& frame);
  // 本端发现的帧级错误（1001 / 1002 / 1003 / 1007）。发出时 ERROR 帧已发送、连接正在关闭。
  void protocolError(fwds::ErrorCode code, const QString& message);

 private slots:
  void onReadyRead();

 private:
  QAbstractSocket* socket_;
  FrameDecoder decoder_;
  quint32 maxBody_;
  quint64 sendSeq_ = 0;  // 已发送的最后一帧序号
  quint64 recvSeq_ = 0;  // 已接收的最后一帧序号
  bool closed_ = false;
};

}  // namespace fwds
