#include "server/business/chunk_service.h"

#include <QFile>

#include "common/log.h"

namespace fwds {

ChunkService::ChunkService(TcpServer* server, const ProtocolParams& params, QObject* parent)
    : QObject(parent), params_(params) {
  connect(server, &TcpServer::sessionOpened, this, [this](Session* session) {
    connect(session, &Session::stateChanged, this, &ChunkService::onSessionStateChanged);
    connect(session, &Session::frameReceived, this, &ChunkService::onFrame);
  });
  connect(server, &TcpServer::sessionClosed, this,
          [this](Session* session, const QString&) { onSessionClosed(session); });
}

bool ChunkService::assign(const QString& deviceId, qint64 releaseId, const StoredPackage& package) {
  Session* session = online_.value(deviceId, nullptr);
  if (!session) {
    qCWarning(lcApp).noquote() << "device" << deviceId << "is offline, update not dispatched";
    return false;
  }
  Assignment assignment;
  assignment.releaseId = releaseId;
  assignment.package = package;
  if (!sendNotify(session, assignment)) return false;
  assignments_.insert(deviceId, assignment);
  return true;
}

bool ChunkService::cancel(const QString& deviceId, const QString& reason) {
  const auto it = assignments_.constFind(deviceId);
  if (it == assignments_.constEnd()) return false;

  Session* session = online_.value(deviceId, nullptr);
  if (session) {
    UpdateCancel message;
    message.deviceId = deviceId;
    message.releaseId = it->releaseId;
    message.pkgId = it->package.manifest.pkgId;
    message.reason = reason;
    session->send(MsgType::UpdateCancel, encodeUpdateCancel(message));
  }
  qCInfo(lcApp).noquote() << "update cancelled for" << deviceId << "reason:" << reason;
  cancelled_.insert(deviceId, it->package.manifest.pkgId);
  assignments_.erase(it);
  return true;
}

void ChunkService::finish(const QString& deviceId, const QString& pkgId) {
  const auto it = assignments_.constFind(deviceId);
  if (it != assignments_.constEnd() && it->package.manifest.pkgId == pkgId) assignments_.erase(it);
}

QString ChunkService::assignedPackage(const QString& deviceId) const {
  const auto it = assignments_.constFind(deviceId);
  return it == assignments_.constEnd() ? QString() : it->package.manifest.pkgId;
}

void ChunkService::onSessionStateChanged(Session* session) {
  if (session->state() != Session::State::Online) return;
  const QString deviceId = session->deviceId();
  // 每次心跳也会触发 stateChanged，这条会话已经登记过就不用再处理
  if (online_.value(deviceId, nullptr) == session) return;
  online_.insert(deviceId, session);

  // 设备（重新）登录时还有没完成的下发：把同一个包的通知再发一次。
  // 这不是盲发——这个包在设备上一次在线时已经下发过，设备靠这条通知从断点接着下载
  const auto it = assignments_.constFind(deviceId);
  if (it != assignments_.constEnd()) sendNotify(session, it.value());
}

void ChunkService::onSessionClosed(Session* session) {
  // 只移除“当前登记的那条会话”；被新连接顶替掉的旧会话关闭时不动
  const QString deviceId = session->deviceId();
  if (online_.value(deviceId, nullptr) == session) online_.remove(deviceId);
}

void ChunkService::onFrame(Session* session, const Frame& frame) {
  if (static_cast<MsgType>(frame.type) == MsgType::ChunkReq) {
    handleChunkRequest(session, frame.body);
  }
  // PROGRESS / RESULT / ALERT 由事件入库模块（EventStore）处理，这里不管
}

void ChunkService::handleChunkRequest(Session* session, const QByteArray& body) {
  // ① 格式：不是合法的 CHUNK_REQ 回 1005，不断开
  ChunkRequest request;
  if (!parseChunkRequest(body, &request)) {
    session->sendError(ErrorCode::BadJson);
    return;
  }

  // ② 只能要“当前下发给自己的那个包”。设备 ID 取自这条会话（登录时已和证书核对），
  //    不是请求里自报的，所以一台设备拿不到下发给别的设备的包
  const QString deviceId = session->deviceId();
  const auto it = assignments_.constFind(deviceId);
  if (it == assignments_.constEnd() || it->package.manifest.pkgId != request.pkgId) {
    // 刚取消的包：设备在收到 UPDATE_CANCEL 之前发出的请求还在路上，属于正常的先后顺序，
    // 不记安全事件（用例 ST-26 联调时发现）。其余情况才是越权请求
    if (it == assignments_.constEnd() && cancelled_.value(deviceId) == request.pkgId) {
      qCInfo(lcApp).noquote() << "device" << deviceId
                              << "requested a chunk of the package just cancelled, ignored";
    } else {
      qCWarning(lcSecurity).noquote() << "device" << deviceId
                                      << "requested a package not assigned to it";
    }
    session->sendError(ErrorCode::PkgNotFound);
    return;
  }
  const StoredPackage& package = it->package;
  const Manifest& manifest = package.manifest;

  // ③ 范围：1 ≤ count ≤ 窗口上限，from_index + count 不超过总片数。
  //    用减法比较，避免 from_index + count 溢出
  const int maxCount = qMin(params_.chunkWindow, kMaxChunkWindow);
  if (request.count < 1 || request.count > maxCount || request.fromIndex >= manifest.chunkCount ||
      request.count > manifest.chunkCount - request.fromIndex) {
    session->sendError(ErrorCode::ChunkOutOfRange);
    return;
  }

  // ④ 流控：上一批还积压在发送缓冲里没发完就又来要，这次不发。
  //    正常设备收齐一个窗口才会要下一个，不会走到这里；
  //    不停发请求却不收数据的连接，最多让服务端为它缓存两个窗口的数据
  const qint64 backlogLimit = 2LL * maxCount * (kChunkSize + kChunkDataHeaderSize + kHeaderSize);
  if (session->pendingSendBytes() > backlogLimit) {
    qCWarning(lcNet).noquote() << "device" << deviceId << "requests chunks faster than it reads, ignored";
    return;
  }

  // ⑤ 从 .fwpkg 里按偏移读出每一片并发送
  QFile file(package.filePath);
  if (!file.open(QIODevice::ReadOnly)) {
    qCCritical(lcApp).noquote() << "cannot open firmware package" << package.filePath;
    session->sendError(ErrorCode::PkgNotFound);
    return;
  }
  for (int index = request.fromIndex; index < request.fromIndex + request.count; ++index) {
    const qint64 length = manifest.chunkLength(index);
    const qint64 offset = package.imageOffset + static_cast<qint64>(index) * manifest.chunkSize;
    if (!file.seek(offset)) break;
    const QByteArray data = file.read(length);
    if (data.size() != length) {
      // 文件在导入之后被截断或损坏了：不发残缺的分片
      qCCritical(lcApp).noquote() << "firmware package truncated:" << package.filePath;
      session->sendError(ErrorCode::PkgNotFound);
      return;
    }
    if (!session->send(MsgType::ChunkData, encodeChunkData(manifest.pkgId, index, data))) return;
    ++chunksSent_;
  }
}

bool ChunkService::sendNotify(Session* session, const Assignment& assignment) {
  UpdateNotify notify;
  notify.deviceId = session->deviceId();
  notify.releaseId = assignment.releaseId;
  notify.pkgId = assignment.package.manifest.pkgId;
  notify.manifestRaw = assignment.package.manifestRaw;  // 原样转发，不重新序列化
  notify.signature = assignment.package.signature;
  const bool sent = session->send(MsgType::UpdateNotify, encodeUpdateNotify(notify));
  if (sent) {
    qCInfo(lcApp).noquote() << "UPDATE_NOTIFY sent to" << notify.deviceId << "package" << notify.pkgId;
  }
  return sent;
}

}  // namespace fwds
