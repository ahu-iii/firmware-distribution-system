#include "common/config.h"

#include <QFileInfo>
#include <QRegularExpression>
#include <QSettings>

namespace fwds {

namespace {

// 读一个有范围限制的整数；键不存在时保留 *value 里的默认值。
bool readInt(const QSettings& s, const QString& key, int min, int max, int* value,
             QString* error) {
  if (!s.contains(key)) return true;
  bool ok = false;
  const int v = s.value(key).toString().trimmed().toInt(&ok);
  if (!ok || v < min || v > max) {
    *error = QStringLiteral("配置项 %1 取值非法（允许 %2 ~ %3）").arg(key).arg(min).arg(max);
    return false;
  }
  *value = v;
  return true;
}

// 端口必填，没有默认值。
bool readPort(const QSettings& s, const QString& key, quint16* port, QString* error) {
  bool ok = false;
  const int v = s.value(key).toString().trimmed().toInt(&ok);
  if (!s.contains(key) || !ok || v < 1 || v > 65535) {
    *error = QStringLiteral("配置项 %1 缺失或不是合法端口").arg(key);
    return false;
  }
  *port = static_cast<quint16>(v);
  return true;
}

bool readRequiredString(const QSettings& s, const QString& key, QString* value,
                        QString* error) {
  const QString v = s.value(key).toString().trimmed();
  // 模板里用 <...> 做占位符，没改就启动要报错
  if (v.isEmpty() || v.startsWith(QLatin1Char('<'))) {
    *error = QStringLiteral("配置项 %1 缺失或仍是模板占位符").arg(key);
    return false;
  }
  *value = v;
  return true;
}

bool readProtocol(const QSettings& s, ProtocolParams* p, QString* error) {
  const int kDay = 24 * 3600 * 1000;
  if (!readInt(s, QStringLiteral("protocol/login_timeout_ms"), 1, kDay, &p->loginTimeoutMs, error) ||
      !readInt(s, QStringLiteral("protocol/heartbeat_interval_ms"), 1, kDay, &p->heartbeatIntervalMs, error) ||
      !readInt(s, QStringLiteral("protocol/heartbeat_timeout_ms"), 1, kDay, &p->heartbeatTimeoutMs, error) ||
      !readInt(s, QStringLiteral("protocol/login_ts_window_ms"), 1, kDay, &p->loginTsWindowMs, error)) {
    return false;
  }
  if (p->heartbeatTimeoutMs <= p->heartbeatIntervalMs) {
    *error = QStringLiteral("protocol/heartbeat_timeout_ms 必须大于 heartbeat_interval_ms");
    return false;
  }

  // 帧长上限只能调小，不能超过协议规定的 1 MB；也不能小到装不下一片固件（24 字节头 + 64 KB）
  int maxBody = static_cast<int>(p->maxFrameBody);
  if (!readInt(s, QStringLiteral("protocol/max_frame_body"), static_cast<int>(kMinFrameBody),
               static_cast<int>(kMaxBodyLength), &maxBody, error)) {
    return false;
  }
  p->maxFrameBody = static_cast<quint32>(maxBody);

  // 分片下载：请求窗口不能超过协议规定的 16 片（协议 5.5 节）
  if (!readInt(s, QStringLiteral("protocol/chunk_window"), 1, 16, &p->chunkWindow, error) ||
      !readInt(s, QStringLiteral("protocol/chunk_window_timeout_ms"), 1, kDay,
               &p->chunkWindowTimeoutMs, error) ||
      !readInt(s, QStringLiteral("protocol/chunk_retry_limit"), 1, 100, &p->chunkRetryLimit, error)) {
    return false;
  }

  // 重连退避序列，逗号分隔。QSettings 会把带逗号的值解析成列表。
  const QString key = QStringLiteral("protocol/reconnect_backoff_ms");
  if (s.contains(key)) {
    QList<int> list;
    const QStringList parts = s.value(key).toStringList();
    for (const QString& part : parts) {
      bool ok = false;
      const int v = part.trimmed().toInt(&ok);
      if (!ok || v < 1 || v > kDay) {
        *error = QStringLiteral("配置项 %1 取值非法").arg(key);
        return false;
      }
      list.append(v);
    }
    if (list.isEmpty()) {
      *error = QStringLiteral("配置项 %1 不能为空").arg(key);
      return false;
    }
    p->reconnectBackoffMs = list;
  }
  return true;
}

bool readCertDayLimits(const QSettings& s, TlsConfig* tls, QString* error) {
  return readInt(s, QStringLiteral("tls/max_ca_cert_days"), 1, kMaxConfigurableCertDays,
                 &tls->maxCaCertDays, error) &&
         readInt(s, QStringLiteral("tls/max_cert_days"), 1, kMaxConfigurableCertDays,
                 &tls->maxCertDays, error);
}

// [tls] 是两端共用的 CA 证书、CRL 和有效期上限；本端证书和私钥在各自的段（section）里。
bool readTls(const QSettings& s, const QString& section, TlsConfig* tls, QString* error) {
  return readRequiredString(s, QStringLiteral("tls/ca_file"), &tls->caFile, error) &&
         readRequiredString(s, QStringLiteral("tls/crl_file"), &tls->crlFile, error) &&
         readRequiredString(s, section + QStringLiteral("/cert_file"), &tls->certFile, error) &&
         readRequiredString(s, section + QStringLiteral("/key_file"), &tls->keyFile, error) &&
         readCertDayLimits(s, tls, error);
}

// 固件签名公钥的指纹：SHA-256 的十六进制写法，统一成小写，必须正好 64 个十六进制字符。
bool readFingerprint(const QSettings& s, const QString& key, QString* value, QString* error) {
  if (!readRequiredString(s, key, value, error)) return false;
  *value = value->toLower();
  static const QRegularExpression kFingerprint(QStringLiteral("\\A[0-9a-f]{64}\\z"));
  if (!kFingerprint.match(*value).hasMatch()) {
    *error = QStringLiteral("配置项 %1 必须是 64 个十六进制字符").arg(key);
    return false;
  }
  return true;
}

bool openSettings(const QString& path, QString* error) {
  const QFileInfo info(path);
  if (path.isEmpty() || !info.isFile() || !info.isReadable()) {
    *error = QStringLiteral("配置文件不存在或不可读：%1").arg(path);
    return false;
  }
  return true;
}

}  // namespace

bool loadServerConfig(const QString& path, ServerConfig* out, QString* error) {
  if (!openSettings(path, error)) return false;
  const QSettings s(path, QSettings::IniFormat);
  ServerConfig cfg;

  QString address;
  if (!readRequiredString(s, QStringLiteral("server/listen_address"), &address, error)) return false;
  if (!cfg.listenAddress.setAddress(address)) {
    *error = QStringLiteral("配置项 server/listen_address 不是合法 IP 地址");
    return false;
  }
  if (!readPort(s, QStringLiteral("server/listen_port"), &cfg.listenPort, error)) return false;
  if (!readInt(s, QStringLiteral("server/max_connections"), 1, 100000, &cfg.maxConnections, error) ||
      !readInt(s, QStringLiteral("server/max_connections_per_ip"), 1, 100000,
               &cfg.maxConnectionsPerIp, error)) {
    return false;
  }
  if (!readRequiredString(s, QStringLiteral("server/db_file"), &cfg.dbFile, error) ||
      !readRequiredString(s, QStringLiteral("server/firmware_dir"), &cfg.firmwareDir, error) ||
      !readRequiredString(s, QStringLiteral("server/fsk_pub_file"), &cfg.fskPubFile, error) ||
      !readFingerprint(s, QStringLiteral("server/fsk_pub_sha256"), &cfg.fskPubSha256, error)) {
    return false;
  }
  if (!readInt(s, QStringLiteral("server/login_fail_limit"), 1, 1000, &cfg.loginFailLimit, error) ||
      !readInt(s, QStringLiteral("server/login_fail_window_s"), 1, 86400, &cfg.loginFailWindowS, error) ||
      !readInt(s, QStringLiteral("server/login_lock_s"), 1, 86400, &cfg.loginLockS, error)) {
    return false;
  }
  cfg.auditCheckpointFile =
      s.value(QStringLiteral("server/audit_checkpoint_file")).toString().trimmed();
  if (cfg.auditCheckpointFile.isEmpty()) {
    cfg.auditCheckpointFile = cfg.dbFile + QStringLiteral(".audit-checkpoint");
  }
  // 灰度发布：观察期最长 1 天；同时推送台数 1 ~ 100；失败比例阈值 0 ~ 100（0 表示全量阶段失败一台就暂停）
  int observeS = cfg.rollout.observeMs / 1000;
  if (!readInt(s, QStringLiteral("rollout/observe_s"), 1, 86400, &observeS, error) ||
      !readInt(s, QStringLiteral("rollout/concurrency"), 1, 100, &cfg.rollout.concurrency, error) ||
      !readInt(s, QStringLiteral("rollout/max_failure_pct"), 0, 100, &cfg.rollout.maxFailurePct,
               error)) {
    return false;
  }
  cfg.rollout.observeMs = observeS * 1000;
  cfg.logLevel = s.value(QStringLiteral("log/level"), cfg.logLevel).toString().trimmed().toUpper();
  if (!readProtocol(s, &cfg.protocol, error)) return false;
  if (!readTls(s, QStringLiteral("server"), &cfg.tls, error)) return false;

  *out = cfg;
  return true;
}

bool loadClientConfig(const QString& path, ClientConfig* out, QString* error) {
  if (!openSettings(path, error)) return false;
  const QSettings s(path, QSettings::IniFormat);
  ClientConfig cfg;

  if (!readRequiredString(s, QStringLiteral("client/server_host"), &cfg.serverHost, error) ||
      !readPort(s, QStringLiteral("client/server_port"), &cfg.serverPort, error) ||
      !readRequiredString(s, QStringLiteral("client/device_id"), &cfg.deviceId, error) ||
      !readRequiredString(s, QStringLiteral("client/model"), &cfg.model, error) ||
      !readRequiredString(s, QStringLiteral("client/data_dir"), &cfg.dataDir, error) ||
      !readRequiredString(s, QStringLiteral("client/fsk_pub_file"), &cfg.fskPubFile, error) ||
      !readFingerprint(s, QStringLiteral("client/fsk_pub_sha256"), &cfg.fskPubSha256, error) ||
      !readInt(s, QStringLiteral("client/reboot_delay_ms"), 0, 60000, &cfg.rebootDelayMs, error)) {
    return false;
  }
  cfg.logLevel = s.value(QStringLiteral("log/level"), cfg.logLevel).toString().trimmed().toUpper();
  if (!readProtocol(s, &cfg.protocol, error)) return false;
  if (!readTls(s, QStringLiteral("client"), &cfg.tls, error)) return false;

  *out = cfg;
  return true;
}

bool loadSignerConfig(const QString& path, SignerConfig* out, QString* error) {
  if (!openSettings(path, error)) return false;
  const QSettings s(path, QSettings::IniFormat);
  TlsConfig tls;
  SignerConfig cfg;
  if (!readCertDayLimits(s, &tls, error) ||
      !readInt(s, QStringLiteral("signer/crl_valid_days"), 1, 365, &cfg.crlValidDays, error)) {
    return false;
  }
  cfg.maxCaCertDays = tls.maxCaCertDays;
  cfg.maxCertDays = tls.maxCertDays;
  *out = cfg;
  return true;
}

}  // namespace fwds
