// DeviceAudit：把设备侧发生的事写进防篡改审计日志（设计第 13 章，检查项 2-x“日志留痕”）。
// 操作员的操作由 AdminService 记，发布的自动推进由 RolloutManager 记；这里记的是设备带来的四类：
//   CONN      设备登录成功（带上报的固件版本）、已登录的连接断开
//   HB        心跳超时，判为离线
//   UPGRADE   设备开始升级（PROGRESS 里的 NOTIFIED）、升级结果（RESULT）
//   SECURITY  设备上报的安全告警（ALERT）；TLS 握手失败、证书校验失败、登录被拒、TLS 记录校验失败
// 来源 source 记设备的 IP，操作者 actor 记设备 ID（没登录的连接记证书里的名称，也没有就记 -）。
// 事件只接 EventStore 入库成功后发出的信号：补传的重复事件不会记第二次，顺序和设备上的序号一致。
// 没登录的连接被拒可能来自攻击（大量握手失败），同一个 IP 每分钟最多记 kMaxRejectsPerMinute 条，
// 超出的只写运行日志，审计日志不会被刷爆。
#pragma once

#include <QHash>
#include <QObject>
#include <QSet>

#include "server/business/device_registry.h"
#include "server/business/event_store.h"
#include "server/net/tcp_server.h"
#include "server/security/audit_service.h"

namespace fwds {

// 同一个 IP 每分钟最多记几条“未登录连接被拒”。
inline constexpr int kMaxRejectsPerMinute = 20;

class DeviceAudit : public QObject {
  Q_OBJECT
 public:
  // 所有指针由调用方持有，必须比 DeviceAudit 活得久。events 可以为空（只记连接类）。
  DeviceAudit(TcpServer* server, EventStore* events, DeviceRegistry* registry, AuditService* audit,
              QObject* parent = nullptr);

 private:
  void onSessionStateChanged(Session* session);
  void onSessionClosed(Session* session, const QString& reason);
  void onResult(const QString& deviceId, qint64 releaseId, const QString& pkgId,
                const QString& result, int code, const QString& detail);
  void onAlert(const QString& deviceId, const QString& pkgId, int code, const QString& detail);
  void onProgress(const QString& deviceId, const QString& pkgId, const QString& state, int progress);

  // 设备事件的来源：设备当前连接的 IP（注册表里登录时记下的）。
  QString addressOf(const QString& deviceId) const;
  // 这个 IP 这一分钟还能不能再记一条“未登录连接被拒”。
  bool allowReject(const QString& address);
  void write(const QString& category, bool warn, const QString& actor, const QString& source,
             const QString& deviceId, const QString& message);

  DeviceRegistry* registry_;
  AuditService* audit_;
  QSet<Session*> loggedIn_;  // 登录成功过、还没关闭的会话
  struct RejectWindow {
    qint64 minute = 0;  // 从 1970 年起的第几分钟
    int count = 0;
  };
  QHash<QString, RejectWindow> rejects_;  // IP → 这一分钟记了几条
};

}  // namespace fwds
