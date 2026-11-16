// HeartbeatMonitor：把连接状态同步到设备注册表（设计第 3 节）。
// 心跳的计时在 Session 里（15 秒没收到心跳就关闭连接），这里负责“连接变了之后改设备表”：
//   会话登录成功 → 记下“设备 ID → 会话”；同一设备的旧连接还在则断开旧的
//   收到心跳     → 更新最后心跳时间和设备上报的升级状态、进度
//   会话关闭     → 设备置为离线并写 HB 日志
//   设备被停用   → 立即断开它现有的连接（设计 11.4 节，用例 ST-04）
#pragma once

#include <QHash>
#include <QObject>

#include "server/business/device_registry.h"
#include "server/net/tcp_server.h"

namespace fwds {

class HeartbeatMonitor : public QObject {
  Q_OBJECT
 public:
  HeartbeatMonitor(TcpServer* server, DeviceRegistry* registry, QObject* parent = nullptr);

 private:
  void onSessionStateChanged(Session* session);
  void onHeartbeat(Session* session, const QByteArray& body);
  void onSessionClosed(Session* session, const QString& reason);
  void onDeviceDisabled(const QString& deviceId);

  DeviceRegistry* registry_;
  QHash<QString, Session*> online_;  // 设备 ID → 它当前已登录的会话
};

}  // namespace fwds
