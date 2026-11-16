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

LoginHandler::LoginHandler(const ProtocolParams& params, QObject* parent)
    : QObject(parent), params_(params) {}

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
    qCCritical(lcSecurity) << "session" << session->id() << deviceId << "LOGIN ts out of window";
    session->rejectLogin(failResult(ErrorCode::TsOutOfWindow));
    return;
  }

  // 上下文绑定（设计 10.6 节）：LOGIN 里自报的设备 ID 必须就是 TLS 握手时出示的那张证书的名称。
  // 否则持有 DEV-002 证书的设备可以自称 DEV-001。
  const PeerIdentity& peer = session->peerIdentity();
  if (peer.name.isEmpty() || deviceId != peer.name) {
    qCCritical(lcSecurity) << "session" << session->id() << "LOGIN device_id" << deviceId
                           << "does not match certificate name" << peer.name;
    session->rejectLogin(failResult(ErrorCode::IdCertMismatch));
    return;
  }

  // TODO(DeviceRegistry)：已注册、未停用、证书指纹（peer.fingerprint）与注册表一致，否则 2005
  // TODO(安全层)：许可证签名与设备 ID，否则 2006
  // TODO(ConnLimiter)：登录失败计数与锁定，2007

  session->setDeviceId(deviceId);

  QJsonObject result;
  result.insert(QStringLiteral("result"), QStringLiteral("OK"));
  result.insert(QStringLiteral("code"), 0);
  result.insert(QStringLiteral("session_id"), newSessionId());
  result.insert(QStringLiteral("heartbeat_interval"), params_.heartbeatIntervalMs / 1000);
  result.insert(QStringLiteral("server_time"), now);
  result.insert(QStringLiteral("event_ack"), 0);  // TODO(EventStore)：该设备已连续收到的最大事件序号
  session->acceptLogin(result);
  qCInfo(lcNet) << "session" << session->id() << deviceId << "login ok";
}

}  // namespace fwds
