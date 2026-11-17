#include "client/business/downloader.h"

#include <QJsonDocument>
#include <QJsonObject>

#include "common/log.h"
#include "common/security/manifest_verifier.h"
#include "common/update_messages.h"

namespace fwds {

Downloader::Downloader(const QString& deviceId, const UpdateValidator& validator,
                       ResumeStore* store, const ProtocolParams& params, SendFn send,
                       QObject* parent)
    : QObject(parent),
      deviceId_(deviceId),
      validator_(validator),
      store_(store),
      params_(params),
      send_(std::move(send)) {
  recheckTimer_.setInterval(0);
  windowTimer_.setSingleShot(true);
  connect(&recheckTimer_, &QTimer::timeout, this, &Downloader::recheckSlice);
  // 窗口超时：这一批没收齐（丢了、服务端忙），从第一个缺失的分片重新要
  connect(&windowTimer_, &QTimer::timeout, this, [this]() {
    qCWarning(lcNet) << "chunk window timed out, requesting again";
    requestWindow();
  });
}

void Downloader::handleFrame(const Frame& frame) {
  switch (static_cast<MsgType>(frame.type)) {
    case MsgType::UpdateNotify: onUpdateNotify(frame.body); break;
    case MsgType::UpdateCancel: onUpdateCancel(frame.body); break;
    case MsgType::ChunkData: onChunkData(frame.body); break;
    case MsgType::Error: onServerError(frame.body); break;
    default: break;  // 其余类型不归下载模块管
  }
}

void Downloader::setOnline(bool online) {
  if (online_ == online) return;
  online_ = online;
  if (online) return;  // 上线后不主动做事，等服务端的 UPDATE_NOTIFY

  // 断线：停掉窗口计时，把进度落盘，等重连后续传
  windowTimer_.stop();
  windowCount_ = 0;
  if (active()) {
    awaitingNotify_ = true;
    QString error;
    if (!store_->flush(&error)) qCWarning(lcApp).noquote() << "cannot save progress:" << error;
    qCInfo(lcNet) << "connection lost, download paused at" << progress() << "%";
  }
}

void Downloader::onUpdateNotify(const QByteArray& body) {
  UpdateNotify notify;
  if (!parseUpdateNotify(body, &notify)) {
    sendError(ErrorCode::BadJson);
    return;
  }
  // ① 先确认是发给自己的（协议 5.4 节）
  if (notify.deviceId != deviceId_) {
    qCCritical(lcSecurity) << "UPDATE_NOTIFY addressed to another device, ignored";
    return;
  }

  // ② 正在这条连接上下载：同一个包的重复通知不用理会，别的包回 3013 BUSY。
  //    断线重连后（awaitingNotify_）不走这里：以服务端重新下发的通知为准
  if (active() && !awaitingNotify_) {
    if (notify.pkgId != manifest_.pkgId) {
      sendError(ErrorCode::Busy);
    }
    return;
  }

  // ③ 先验签，后解析，再查型号和防降级。任何一项不过都不下载
  stopTimers();
  awaitingNotify_ = false;
  Manifest manifest;
  QString detail;
  const ErrorCode verdict =
      validator_.check(notify.manifestRaw, notify.signature, &manifest, &detail);
  if (verdict != ErrorCode::Ok) {
    // 验签失败和降级属于安全事件，要告警；型号不符、内容不合规只报失败（协议 6.2 节）
    const bool alert = verdict == ErrorCode::SigInvalid || verdict == ErrorCode::RollbackAttempt;
    fail(verdict, detail, alert);
    return;
  }
  // 通知里明文带的 pkg_id 必须和签名保护的 manifest 里的一致
  if (manifest.pkgId != notify.pkgId) {
    fail(ErrorCode::ManifestInvalid, QStringLiteral("通知中的 pkg_id 与 manifest 不一致"), false);
    return;
  }

  // ④ 打开断点。同一份 manifest 有断点就接着下，否则从头开始
  if (!store_->open(manifest, notify.manifestRaw, &detail)) {
    fail(ErrorCode::DiskFull, detail, false);
    return;
  }
  manifest_ = manifest;
  manifestRaw_ = notify.manifestRaw;
  signature_ = notify.signature;
  mismatches_.clear();
  lastPercent_ = -1;
  setState(State::Notified);

  // ⑤ 续传前把断点记录里“已完成”的分片重新校验一遍，分段做，不长时间占着界面线程
  recheckNext_ = 0;
  recheckTimer_.start();
}

void Downloader::recheckSlice() {
  // 每次最多查 16 片（约 1 MB），然后回到事件循环
  recheckNext_ = store_->recheck(recheckNext_, kMaxChunkWindow);
  if (recheckNext_ < manifest_.chunkCount) return;  // 没查完，定时器会再触发

  recheckTimer_.stop();
  setState(State::Downloading);
  reportProgress();
  requestWindow();
}

void Downloader::requestWindow() {
  if (state_ != State::Downloading) return;
  windowTimer_.stop();
  windowCount_ = 0;

  const ChunkBitmap& bitmap = store_->bitmap();
  if (bitmap.isComplete()) {
    finishDownload();
    return;
  }
  if (!online_ || awaitingNotify_) return;  // 断线中，等重连后的通知

  // 从第一个缺失的分片开始，要一段连续缺失的分片，最多一个窗口
  const int from = bitmap.firstMissing();
  const int window = qMin(params_.chunkWindow, kMaxChunkWindow);
  int count = 0;
  while (count < window && from + count < bitmap.size() && !bitmap.test(from + count)) ++count;

  ChunkRequest request;
  request.pkgId = manifest_.pkgId;
  request.fromIndex = from;
  request.count = count;
  if (!send_(MsgType::ChunkReq, encodeChunkRequest(request))) return;  // 发不出去说明刚断线

  windowFrom_ = from;
  windowCount_ = count;
  windowHandled_ = 0;
  windowTimer_.start(params_.chunkWindowTimeoutMs);
  qCDebug(lcNet) << "CHUNK_REQ from_index" << from << "count" << count;
}

void Downloader::onChunkData(const QByteArray& body) {
  if (state_ != State::Downloading || windowCount_ == 0) return;  // 没在等分片

  ChunkData chunk;
  if (!parseChunkData(body, &chunk)) {
    qCWarning(lcSecurity) << "malformed CHUNK_DATA dropped";
    return;
  }
  // 只接受“当前这个包、当前这个窗口里、还没完成”的分片，其余丢弃
  const bool inWindow = chunk.index >= windowFrom_ && chunk.index < windowFrom_ + windowCount_;
  if (chunk.pkgId != manifest_.pkgId || !inWindow || store_->bitmap().test(chunk.index)) return;
  ++windowHandled_;

  // 逐片校验：长度和 SHA-256 都要和（已验签的）manifest 一致，通过了才写盘
  if (chunkMatches(manifest_, chunk.index, chunk.data)) {
    QString error;
    if (!store_->writeChunk(chunk.index, chunk.data, &error)) {
      fail(ErrorCode::DiskFull, error, false);
      return;
    }
    mismatches_.remove(chunk.index);
    reportProgress();
  } else {
    // 哈希不符：这一片不写盘，仍算缺失，下一个请求会从它开始重新要
    const int times = ++mismatches_[chunk.index];
    qCWarning(lcSecurity) << "chunk" << chunk.index << "hash mismatch, attempt" << times;
    if (times >= params_.chunkRetryLimit) {
      store_->discard();
      fail(ErrorCode::ChunkTampered,
           QStringLiteral("分片 %1 连续 %2 次哈希不符").arg(chunk.index).arg(times), true);
      return;
    }
  }

  // 这个窗口处理完了，要下一个
  if (windowHandled_ >= windowCount_) requestWindow();
}

void Downloader::onUpdateCancel(const QByteArray& body) {
  UpdateCancel cancel;
  if (!parseUpdateCancel(body, &cancel)) return;
  // 只在 NOTIFIED、DOWNLOADING 状态处理，而且必须是针对当前这个包的（协议 5.4 节）
  if (!active() || cancel.deviceId != deviceId_ || cancel.pkgId != manifest_.pkgId) return;
  store_->discard();  // 删除临时文件
  fail(ErrorCode::Cancelled, QStringLiteral("服务端取消升级：%1").arg(cancel.reason.left(64)), false);
}

void Downloader::onServerError(const QByteArray& body) {
  if (state_ != State::Downloading) return;
  const int code = QJsonDocument::fromJson(body).object().value(QStringLiteral("code")).toInt();
  // 服务端说这个包已经不再下发给本设备，或请求越界：继续要下去没有意义
  if (code == static_cast<int>(ErrorCode::PkgNotFound) ||
      code == static_cast<int>(ErrorCode::ChunkOutOfRange)) {
    store_->close();  // 断点保留
    fail(static_cast<ErrorCode>(code), QStringLiteral("服务端拒绝分片请求"), false);
  }
}

void Downloader::finishDownload() {
  stopTimers();
  QString error;
  if (!store_->flush(&error)) {
    fail(ErrorCode::DiskFull, error, false);
    return;
  }
  qCInfo(lcApp).noquote() << "all chunks downloaded for" << manifest_.pkgId;
  setState(State::Downloaded);
  emit downloadCompleted(store_->partPath());
}

void Downloader::fail(ErrorCode code, const QString& detail, bool alert) {
  stopTimers();
  awaitingNotify_ = false;
  qCWarning(alert ? lcSecurity() : lcApp()).noquote()
      << "update failed:" << errorName(code) << detail;
  setState(State::Failed);
  if (alert) emit alertRaised(static_cast<int>(code), detail);
  emit failed(static_cast<int>(code), detail);
}

void Downloader::sendError(ErrorCode code) {
  // 1005 和 3xxx 的 ERROR 只是告知对方，不关闭连接（协议 5.8 节）
  QJsonObject body;
  body.insert(QStringLiteral("code"), static_cast<int>(code));
  body.insert(QStringLiteral("message"), QString::fromLatin1(errorName(code)));
  send_(MsgType::Error, QJsonDocument(body).toJson(QJsonDocument::Compact));
}

void Downloader::stopTimers() {
  recheckTimer_.stop();
  windowTimer_.stop();
  windowCount_ = 0;
}

void Downloader::setState(State state) {
  if (state_ == state) return;
  state_ = state;
  emit stateChanged(state);
}

void Downloader::reportProgress() {
  const int percent = progress();
  if (percent == lastPercent_) return;
  lastPercent_ = percent;
  emit progressChanged(percent);
}

QString Downloader::stateName() const {
  switch (state_) {
    case State::Idle: return QStringLiteral("IDLE");
    case State::Notified: return QStringLiteral("NOTIFIED");
    case State::Downloading: return QStringLiteral("DOWNLOADING");
    case State::Downloaded: return QStringLiteral("VERIFYING");  // 下一步是整包校验
    case State::Failed: return QStringLiteral("FAILED");
  }
  return QString();
}

int Downloader::progress() const {
  const ChunkBitmap& bitmap = store_->bitmap();
  if (state_ == State::Idle || state_ == State::Failed || bitmap.size() == 0) return 0;
  return static_cast<int>(static_cast<qint64>(bitmap.doneCount()) * 100 / bitmap.size());
}

}  // namespace fwds
