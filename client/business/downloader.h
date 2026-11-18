// Downloader：设备端的固件下载（设计 4.3 节；升级状态机里 NOTIFIED、DOWNLOADING 两个状态）。
// 流程：
//   收到 UPDATE_NOTIFY → 先验 manifest 签名、型号、防降级（UpdateValidator），不过就不下载
//   → 打开断点（ResumeStore），把已下载的分片重新校验一遍
//   → 循环：CHUNK_REQ 要一个窗口 → 每收到一片 CHUNK_DATA 先比对哈希再写盘 → 窗口收齐要下一个
//   → 全部分片收齐，交给后面的整包校验和写入。
// 断线时只是暂停：进度已经落盘，重连登录后服务端会把同一个包的通知再发一次，从第一个缺失的分片接着要。
//
// 整个类由事件驱动：收到帧、定时器到点才做一小段事然后返回，没有任何等待网络的循环；
// 重新校验断点这种耗时的事也切成小段做。所以服务端断开或迟迟不回数据时，界面线程不会卡住。
#pragma once

#include <QHash>
#include <QObject>
#include <QTimer>
#include <functional>

#include "client/security/update_validator.h"
#include "client/storage/resume_store.h"
#include "common/config.h"
#include "common/protocol.h"

namespace fwds {

class Downloader : public QObject {
  Q_OBJECT
 public:
  enum class State {
    Idle,         // 空闲
    Notified,     // 通知已通过检查，正在准备断点（重新校验已下载的分片）
    Downloading,  // 下载中（断线时停在这个状态等待续传）
    Downloaded,   // 分片全部收齐并逐片校验通过，等待整包校验和写入
    Failed,       // 本次升级已放弃，原固件不受影响
  };

  // 发送一帧的函数，由网络层提供（TcpClient::send）。不在线时返回 false。
  using SendFn = std::function<bool(MsgType, const QByteArray&)>;

  // validator、store 由调用方持有，必须比 Downloader 活得久。
  Downloader(const QString& deviceId, const UpdateValidator& validator, ResumeStore* store,
             const ProtocolParams& params, SendFn send, QObject* parent = nullptr);

  // 网络层收到的业务帧交到这里：UPDATE_NOTIFY、UPDATE_CANCEL、CHUNK_DATA、ERROR。
  void handleFrame(const fwds::Frame& frame);

  // 连接状态变化：true 表示已登录在线，false 表示断线。
  void setOnline(bool online);

  State state() const { return state_; }
  // 协议 6.1 节的状态名，心跳和 PROGRESS 事件里上报用。
  QString stateName() const;
  // 下载进度 0 ~ 100。
  int progress() const;
  // 当前（或最近一次）下载的固件的 manifest，已验签。
  const Manifest& manifest() const { return manifest_; }
  // 这份 manifest 的原始字节和签名（通知里带来的）。写入分区时原样保存，Bootloader 启动时再验。
  const QByteArray& manifestRaw() const { return manifestRaw_; }
  const QByteArray& signature() const { return signature_; }
  // 最近一条发给本设备的 UPDATE_NOTIFY 里的包 ID 和发布号。验签之前就记下，
  // 通知没通过检查时上报的 RESULT / ALERT 也能说明是哪个包。
  const QString& notifiedPkgId() const { return notifiedPkgId_; }
  qint64 releaseId() const { return releaseId_; }

 signals:
  void stateChanged(fwds::Downloader::State state);
  // 进度百分比变化。
  void progressChanged(int percent);
  // 安全告警（验签失败 3001、降级 3003、分片被篡改 3004），上报 ALERT 用。
  void alertRaised(int code, const QString& detail);
  // 本次升级失败，code 是 3xxx 错误码，上报 RESULT（FAILED）用。
  void failed(int code, const QString& detail);
  // 分片全部收齐。partPath 是下载好的镜像文件，下一步做整包校验后写入非活动分区。
  void downloadCompleted(const QString& partPath);

 private:
  void onUpdateNotify(const QByteArray& body);
  void onUpdateCancel(const QByteArray& body);
  void onChunkData(const QByteArray& body);
  void onServerError(const QByteArray& body);

  void recheckSlice();   // 重新校验一小段断点，没查完就排下一段
  void requestWindow();  // 发 CHUNK_REQ 要下一个窗口；全部收齐则结束下载
  void finishDownload();
  void fail(ErrorCode code, const QString& detail, bool alert);
  void sendError(ErrorCode code);
  void stopTimers();
  void setState(State state);
  void reportProgress();
  bool active() const { return state_ == State::Notified || state_ == State::Downloading; }

  QString deviceId_;
  const UpdateValidator& validator_;
  ResumeStore* store_;
  ProtocolParams params_;
  SendFn send_;

  State state_ = State::Idle;
  bool online_ = false;
  // 断线之后为 true：要等服务端重新发来 UPDATE_NOTIFY 才继续（协议第 9 节）。
  bool awaitingNotify_ = false;
  Manifest manifest_;
  QByteArray manifestRaw_;
  QByteArray signature_;
  QString notifiedPkgId_;
  qint64 releaseId_ = 0;

  QTimer recheckTimer_;  // 间隔为 0：每回到事件循环一次，校验一小段断点
  int recheckNext_ = 0;  // 下一段从哪一片开始校验

  QTimer windowTimer_;      // 一个窗口等不齐的时限
  int windowFrom_ = 0;      // 当前窗口的第一片
  int windowCount_ = 0;     // 当前窗口要了几片；0 表示没有在等的窗口
  int windowHandled_ = 0;   // 当前窗口已经处理了几片（写盘或判为哈希不符）

  QHash<int, int> mismatches_;  // 分片序号 → 哈希连续不符的次数
  int lastPercent_ = -1;        // 上一次报告的进度，避免重复发信号
};

}  // namespace fwds
