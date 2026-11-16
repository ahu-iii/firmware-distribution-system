#include "server/business/heartbeat_monitor.h"

#include <QJsonDocument>
#include <QJsonObject>

#include "common/log.h"

namespace fwds {

HeartbeatMonitor::HeartbeatMonitor(TcpServer* server, DeviceRegistry* registry, QObject* parent)
    : QObject(parent), registry_(registry) {
  connect(server, &TcpServer::sessionOpened, this, [this](Session* session) {
    connect(session, &Session::stateChanged, this, &HeartbeatMonitor::onSessionStateChanged);
    connect(session, &Session::heartbeatReceived, this, &HeartbeatMonitor::onHeartbeat);
  });
  connect(server, &TcpServer::sessionClosed, this, &HeartbeatMonitor::onSessionClosed);
  connect(registry, &DeviceRegistry::deviceDisabled, this, &HeartbeatMonitor::onDeviceDisabled);
}

void HeartbeatMonitor::onSessionStateChanged(Session* session) {
  if (session->state() != Session::State::Online) return;
  const QString deviceId = session->deviceId();
  Session* previous = online_.value(deviceId, nullptr);
  if (previous == session) return;  // 心跳也会触发 stateChanged，已经登记过就不用再处理

  online_.insert(deviceId, session);
  if (previous) {
    // 同一台设备重新连了上来（常见于设备侧断网后重连，而旧连接在服务端还没超时）：以新连接为准
    qCWarning(lcNet) << "device" << deviceId << "logged in again, closing its previous session"
                     << previous->id();
    previous->close(QStringLiteral("同一设备重新登录"));
  }
}

void HeartbeatMonitor::onHeartbeat(Session* session, const QByteArray& body) {
  // 心跳内容只用于界面显示，格式不对就当作没有上报，不影响连接
  const QJsonObject status = QJsonDocument::fromJson(body).object();
  const QString state = status.value(QStringLiteral("state")).toString().left(32);
  const int progress = qBound(-1, status.value(QStringLiteral("progress")).toInt(-1), 100);
  registry_->markHeartbeat(session->deviceId(), state, progress);
}

void HeartbeatMonitor::onSessionClosed(Session* session, const QString& reason) {
  const QString deviceId = session->deviceId();
  // 只有“当前登记的那条连接”关闭才算设备下线；被新连接顶替掉的旧连接关闭时不动设备状态
  if (deviceId.isEmpty() || online_.value(deviceId, nullptr) != session) return;
  online_.remove(deviceId);
  registry_->markOffline(deviceId);
  qCInfo(lcNet).noquote() << "[HB] device" << deviceId << "offline:" << reason;
}

void HeartbeatMonitor::onDeviceDisabled(const QString& deviceId) {
  Session* session = online_.value(deviceId, nullptr);
  if (!session) return;
  qCWarning(lcSecurity) << "device" << deviceId << "disabled, closing its session" << session->id();
  session->close(QStringLiteral("设备已停用"));
}

}  // namespace fwds
