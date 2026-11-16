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

struct ServerConfig {
  QHostAddress listenAddress;
  quint16 listenPort = 0;
  int maxConnections = 200;
  int maxConnectionsPerIp = 5;
  QString logLevel = QStringLiteral("INFO");
  ProtocolParams protocol;
};

struct ClientConfig {
  QString serverHost;
  quint16 serverPort = 0;
  QString deviceId;
  QString model;
  QString logLevel = QStringLiteral("INFO");
  ProtocolParams protocol;
};

// 读取并校验配置。必填项缺失或取值非法时返回 false，error 说明是哪一项。
bool loadServerConfig(const QString& path, ServerConfig* out, QString* error);
bool loadClientConfig(const QString& path, ClientConfig* out, QString* error);

}  // namespace fwds
