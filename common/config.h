// 配置加载：所有地址、端口和协议参数都来自 --config 指定的 INI 文件，
// 源码里不写死。模板见 deploy/config/。
#pragma once

#include <QHostAddress>
#include <QList>
#include <QString>

#include "common/protocol.h"

namespace fwds {

// 协议参数（协议文档第 8 节），初值为文档给出的默认值，配置文件可覆盖。
struct ProtocolParams {
  int loginTimeoutMs = 10000;       // 连接建立到登录完成的时限
  int heartbeatIntervalMs = 5000;   // 客户端心跳间隔
  int heartbeatTimeoutMs = 15000;   // 服务端离线判定 / 客户端等应答时限
  int loginTsWindowMs = 60000;      // LOGIN 时间戳窗口
  quint32 maxFrameBody = kMaxBodyLength;
  QList<int> reconnectBackoffMs = {1000, 2000, 4000, 8000, 16000, 30000};
};

// TLS 材料的位置和证书有效期上限（设计 10.2、11.3 节）。
// 这里只有文件路径；私钥口令不进配置文件，由环境变量注入。
struct TlsConfig {
  QString caFile;    // 自建 CA 根证书（PEM）
  QString crlFile;   // 吊销列表（PEM）
  QString certFile;  // 本端证书（PEM）
  QString keyFile;   // 本端私钥（AES-256-GCM 封装）
  // 接受的证书有效期上限（天）。课程规定的上限确定后只改配置，不改代码。
  int maxCaCertDays = 365;
  int maxCertDays = 90;
};

struct ServerConfig {
  QHostAddress listenAddress;
  quint16 listenPort = 0;
  int maxConnections = 200;
  int maxConnectionsPerIp = 5;
  QString logLevel = QStringLiteral("INFO");
  ProtocolParams protocol;
  TlsConfig tls;
};

struct ClientConfig {
  QString serverHost;
  quint16 serverPort = 0;
  QString deviceId;
  QString model;
  QString logLevel = QStringLiteral("INFO");
  ProtocolParams protocol;
  TlsConfig tls;
};

// 读取并校验配置。必填项缺失或取值非法时返回 false，error 说明是哪一项。
bool loadServerConfig(const QString& path, ServerConfig* out, QString* error);
bool loadClientConfig(const QString& path, ClientConfig* out, QString* error);

// 证书有效期上限的允许范围（天）。
inline constexpr int kMaxConfigurableCertDays = 3650;

// 签发工具 fwds-signer 用到的配置：[tls] 里的两个有效期上限（与两端校验时用的是同一组数），
// 以及 [signer] 里 CRL 的有效天数。配置文件对签发工具是可选的，不给就用这里的默认值。
struct SignerConfig {
  int maxCaCertDays = 365;
  int maxCertDays = 90;
  int crlValidDays = 30;
};
bool loadSignerConfig(const QString& path, SignerConfig* out, QString* error);

}  // namespace fwds
