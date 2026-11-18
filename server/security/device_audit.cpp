#include "server/security/device_audit.h"

#include <QDateTime>

#include "common/log.h"

namespace fwds {

namespace {

// 没登录就被关掉的连接里，这几种原因是安全事件；超时、网络错误、对端自己断开不算
bool isSecurityRejection(const QString& reason) {
  return reason == QStringLiteral("TLS 握手失败") || reason == QStringLiteral("证书校验失败") ||
         reason == QStringLiteral("TLS 记录校验失败") || reason.startsWith(QStringLiteral("登录失败"));
}

}  // namespace

DeviceAudit::DeviceAudit(TcpServer* server, EventStore* events, DeviceRegistry* registry,
                         AuditService* audit, QObject* parent)
    : QObject(parent), registry_(registry), audit_(audit) {
  connect(server, &TcpServer::sessionOpened, this, [this](Session* session) {
    connect(session, &Session::stateChanged, this, &DeviceAudit::onSessionStateChanged);
  });
  connect(server, &TcpServer::sessionClosed, this, &DeviceAudit::onSessionClosed);
  if (events) {
    connect(events, &EventStore::resultStored, this, &DeviceAudit::onResult);
    connect(events, &EventStore::alertStored, this, &DeviceAudit::onAlert);
    connect(events, &EventStore::progressStored, this, &DeviceAudit::onProgress);
  }
}

void DeviceAudit::onSessionStateChanged(Session* session) {
  if (session->state() != Session::State::Online) return;
  if (loggedIn_.contains(session)) return;  // 每次心跳也会触发 stateChanged，只记第一次
  loggedIn_.insert(session);
  DeviceRecord record;
  registry_->find(session->deviceId(), &record);
  write(audit::kConn, false, session->deviceId(), session->peerAddress().toString(),
        session->deviceId(),
        QStringLiteral("设备登录，固件 %1（安全版本号 %2）")
            .arg(record.currentVersion.isEmpty() ? QStringLiteral("无") : record.currentVersion)
            .arg(record.securityVersion));
}

void DeviceAudit::onSessionClosed(Session* session, const QString& reason) {
  const QString address = session->peerAddress().toString();
  if (loggedIn_.remove(session)) {
    // 登录过的连接断开：心跳超时记 HB，密文被改记 SECURITY，其余（设备关闭、重启、网络断开）记 CONN
    const QString deviceId = session->deviceId();
    if (reason == QStringLiteral("心跳超时")) {
      write(audit::kHeartbeat, true, deviceId, address, deviceId, QStringLiteral("心跳超时，判为离线"));
    } else if (reason == QStringLiteral("TLS 记录校验失败")) {
      write(audit::kSecurity, true, deviceId, address, deviceId,
            QStringLiteral("TLS 记录校验失败（密文被改动或重放），连接已断开"));
    } else {
      write(audit::kConn, false, deviceId, address, deviceId, QStringLiteral("连接断开：%1").arg(reason));
    }
    return;
  }
  // 没登录就被关掉的连接：只记安全相关的原因，并限制每个 IP 的条数
  if (!isSecurityRejection(reason)) return;
  if (!allowReject(address)) {
    qCWarning(lcSecurity).noquote() << "too many rejected connections from" << address
                                    << ", not written to the audit log:" << reason;
    return;
  }
  // 握手通过了才有证书里的名称；登录被拒时它就是来登录的那台设备
  const QString name = session->peerIdentity().name;
  write(audit::kSecurity, true, name.isEmpty() ? QStringLiteral("-") : name, address, name,
        QStringLiteral("连接被拒：%1").arg(reason));
}

void DeviceAudit::onResult(const QString& deviceId, qint64 releaseId, const QString& pkgId,
                           const QString& result, int code, const QString& detail) {
  QString message = QStringLiteral("升级结果 %1，发布 #%2，包 %3")
                        .arg(result)
                        .arg(releaseId)
                        .arg(pkgId.isEmpty() ? QStringLiteral("（设备未报）") : pkgId);
  if (code != 0) message += QStringLiteral("，错误码 %1 %2").arg(code).arg(detail.left(120));
  write(audit::kUpgrade, result != QLatin1String("SUCCESS"), deviceId, addressOf(deviceId), deviceId,
        message);
}

void DeviceAudit::onAlert(const QString& deviceId, const QString& pkgId, int code,
                          const QString& detail) {
  write(audit::kSecurity, true, deviceId, addressOf(deviceId), deviceId,
        QStringLiteral("设备安全告警 %1：%2（包 %3）")
            .arg(code)
            .arg(detail.left(120), pkgId.isEmpty() ? QStringLiteral("-") : pkgId));
}

void DeviceAudit::onProgress(const QString& deviceId, const QString& pkgId, const QString& state,
                             int progress) {
  Q_UNUSED(progress);
  // 进度事件很多，审计日志只记“开始升级”这一条；进度本身在设备事件和设备监控页里看
  if (state != QLatin1String("NOTIFIED")) return;
  write(audit::kUpgrade, false, deviceId, addressOf(deviceId), deviceId,
        QStringLiteral("收到升级通知并检查通过，开始下载 包 %1").arg(pkgId));
}

QString DeviceAudit::addressOf(const QString& deviceId) const {
  DeviceRecord record;
  if (!registry_->find(deviceId, &record) || record.peerAddress.isEmpty()) return QStringLiteral("-");
  return record.peerAddress;
}

bool DeviceAudit::allowReject(const QString& address) {
  const qint64 minute = QDateTime::currentSecsSinceEpoch() / 60;
  RejectWindow& window = rejects_[address];
  if (window.minute != minute) {
    window.minute = minute;
    window.count = 0;
  }
  if (window.count >= kMaxRejectsPerMinute) return false;
  ++window.count;
  // 来过的 IP 多了就清掉不是这一分钟的，表不会无限长
  if (rejects_.size() > 1000) {
    rejects_.removeIf([minute](const auto& item) { return item.value().minute != minute; });
  }
  return true;
}

void DeviceAudit::write(const QString& category, bool warn, const QString& actor,
                        const QString& source, const QString& deviceId, const QString& message) {
  audit_->append(category, warn ? QStringLiteral("WARN") : QStringLiteral("INFO"), actor, source,
                 deviceId, message);
}

}  // namespace fwds
