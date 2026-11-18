#include "server/business/login_handler.h"

#include <QJsonDocument>
#include <QRandomGenerator>

#include "common/log.h"

namespace fwds {

namespace {

QJsonObject failResult(ErrorCode code) {
  QJsonObject r;
  r.insert(QStringLiteral("result"), QStringLiteral("FAIL"));
  r.insert(QStringLiteral("code"), static_cast<int>(code));
  return r;
}

// 会话 ID：16 字节系统随机数的十六进制。QRandomGenerator::system() 取自操作系统的随机源。
QString newSessionId() {
  quint32 words[4];
  QRandomGenerator::system()->fillRange(words);
  return QString::fromLatin1(
      QByteArray(reinterpret_cast<const char*>(words), sizeof(words)).toHex());
}

}  // namespace

LoginHandler::LoginHandler(const ProtocolParams& params, DeviceRegistry* registry,
                           LoginThrottle* throttle, LicenseVerifier* license, QObject* parent)
    : QObject(parent), params_(params), registry_(registry), throttle_(throttle), license_(license) {}

// 失败锁定按两个键计数：证书里的设备 ID、对端 IP。
// 设备 ID 用证书里的而不是 LOGIN 里自报的：否则持有 DEV-002 证书的人反复自称 DEV-001，
// 就能把 DEV-001 锁在外面。
static QString idKey(const QString& certName) { return QStringLiteral("id:") + certName; }
static QString ipKey(const Session* session) {
  return QStringLiteral("ip:") + session->peerAddress().toString();
}

void LoginHandler::rejectAndCount(Session* session, ErrorCode code, const QString& certName,
                                  qint64 nowMs) {
  const bool idLocked = throttle_->recordFailure(idKey(certName), nowMs);
  const bool ipLocked = throttle_->recordFailure(ipKey(session), nowMs);
  if (idLocked || ipLocked) {
    qCCritical(lcSecurity).noquote()
        << "too many failed logins, locking" << (idLocked ? "device " + certName : QString())
        << (ipLocked ? "address " + session->peerAddress().toString() : QString());
    if (idLocked) registry_->raiseAlert(certName, QStringLiteral("登录失败次数过多，已锁定"));
  }
  session->rejectLogin(failResult(code));
}

void LoginHandler::handle(Session* session, const QByteArray& body) {
  QJsonParseError parseError;
  const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
  const QJsonObject login = doc.object();
  const QString deviceId = login.value(QStringLiteral("device_id")).toString();
  const QJsonValue ts = login.value(QStringLiteral("ts"));

  if (parseError.error != QJsonParseError::NoError || !doc.isObject() || deviceId.isEmpty() ||
      !ts.isDouble()) {
    qCWarning(lcNet) << "session" << session->id() << "LOGIN body malformed";
    session->rejectLogin(failResult(ErrorCode::BadJson));
    return;
  }

  // 时间戳窗口：挡住录下来过一段时间再重放的 LOGIN
  const qint64 now = QDateTime::currentMSecsSinceEpoch();
  const qint64 diff = now - static_cast<qint64>(ts.toDouble());
  if (diff > params_.loginTsWindowMs || diff < -static_cast<qint64>(params_.loginTsWindowMs)) {
    // deviceId 这时还是设备自报的、没核对过的字符串，写日志前截短
    qCCritical(lcSecurity) << "session" << session->id() << deviceId.left(64)
                           << "LOGIN ts out of window";
    session->rejectLogin(failResult(ErrorCode::TsOutOfWindow));
    return;
  }

  // 上下文绑定（设计 10.6 节）：LOGIN 里自报的设备 ID 必须就是 TLS 握手时出示的那张证书的名称。
  // 否则持有 DEV-002 证书的设备可以自称 DEV-001。
  const PeerIdentity& peer = session->peerIdentity();
  if (peer.name.isEmpty() || deviceId != peer.name) {
    qCCritical(lcSecurity) << "session" << session->id() << "LOGIN device_id" << deviceId.left(64)
                           << "does not match certificate name" << peer.name;
    rejectAndCount(session, ErrorCode::IdCertMismatch, peer.name, now);
    return;
  }

  // 注册表：已注册、未停用、指纹与注册时绑定的一致。三种情况对设备都只回 2005，
  // 不让对方知道具体差在哪；详细原因写服务端日志。
  const DeviceCheck check = registry_->checkLogin(deviceId, peer.fingerprint);
  if (check != DeviceCheck::Ok) {
    const char* reason = check == DeviceCheck::NotRegistered ? "not registered"
                         : check == DeviceCheck::Disabled    ? "disabled"
                                                             : "certificate fingerprint mismatch";
    qCCritical(lcSecurity).noquote() << "session" << session->id() << "LOGIN rejected, device"
                                     << deviceId << reason;
    registry_->raiseAlert(deviceId, check == DeviceCheck::Disabled
                                        ? QStringLiteral("已停用的设备尝试登录")
                                        : QStringLiteral("证书指纹与注册表不符"));
    rejectAndCount(session, ErrorCode::DeviceAuthFailed, peer.name, now);
    return;
  }

  // 许可证：验签模块通过 LicenseVerifier 接入（见 license_verifier.h）
  if (license_) {
    const QByteArray licenseBytes =
        QByteArray::fromBase64(login.value(QStringLiteral("license")).toString().toLatin1());
    const QString reason = license_->check(deviceId, licenseBytes);
    if (!reason.isEmpty()) {
      qCCritical(lcSecurity).noquote() << "session" << session->id() << "LOGIN rejected, device"
                                       << deviceId << "license invalid:" << reason;
      registry_->raiseAlert(deviceId, QStringLiteral("许可证无效"));
      rejectAndCount(session, ErrorCode::LicenseInvalid, peer.name, now);
      return;
    }
  }

  // 失败锁定：锁定期内即使这次材料全对也不放行
  if (throttle_->isLocked(idKey(peer.name), now) || throttle_->isLocked(ipKey(session), now)) {
    qCWarning(lcSecurity) << "session" << session->id() << deviceId << "LOGIN rejected, locked";
    session->rejectLogin(failResult(ErrorCode::DeviceLocked));
    return;
  }

  // 全部通过：登记在线状态。型号以注册表为准，设备自报的不一致时只告警。
  DeviceRecord record;
  registry_->find(deviceId, &record);
  const QString reportedModel = login.value(QStringLiteral("model")).toString();
  if (!reportedModel.isEmpty() && reportedModel != record.model) {
    qCWarning(lcNet) << deviceId << "reports model" << reportedModel.left(32)
                     << "but is registered as" << record.model;
  }
  session->setDeviceId(deviceId);
  registry_->markOnline(deviceId, session->peerAddress().toString(),
                        login.value(QStringLiteral("fw_version")).toString().left(32),
                        login.value(QStringLiteral("security_version")).toInt());

  QJsonObject result;
  result.insert(QStringLiteral("result"), QStringLiteral("OK"));
  result.insert(QStringLiteral("code"), 0);
  result.insert(QStringLiteral("session_id"), newSessionId());
  result.insert(QStringLiteral("heartbeat_interval"), params_.heartbeatIntervalMs / 1000);
  result.insert(QStringLiteral("server_time"), now);
  // 该设备已连续收到的最大事件序号。设备报告的 event_base（它已确认删除到哪里）比这个大时，
  // EventStore 先对账（协议 5.1、5.7 节）。event_base 是可选字段，格式不对按 0 处理
  qint64 eventAck = record.eventAck;
  if (events_) {
    const double base = login.value(QStringLiteral("event_base")).toDouble(0);
    const qint64 eventBase =
        (base >= 0 && base <= 9007199254740992.0 && base == static_cast<qint64>(base))
            ? static_cast<qint64>(base)
            : 0;
    eventAck = events_->reconcileOnLogin(deviceId, eventBase);
  }
  result.insert(QStringLiteral("event_ack"), eventAck);
  session->setEventAck(eventAck);
  session->acceptLogin(result);
  qCInfo(lcNet) << "session" << session->id() << deviceId << "login ok";
}

}  // namespace fwds
