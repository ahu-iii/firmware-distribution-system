// 配置加载：所有地址、端口和协议参数都来自 --config 指定的 INI 文件，
// 源码里不写死。模板见 deploy/config/。
#pragma once

#include <QHostAddress>
#include <QList>
#include <QString>

#include "common/log.h"
#include "common/protocol.h"

namespace fwds {

// 协议参数（协议文档第 8 节），初值为文档给出的默认值，配置文件可覆盖。
struct ProtocolParams {
  int loginTimeoutMs = 10000;       // 连接建立到登录完成的时限
  int heartbeatIntervalMs = 5000;   // 客户端心跳间隔
  int heartbeatTimeoutMs = 15000;   // 服务端离线判定 / 客户端等应答时限
  int loginTsWindowMs = 60000;      // LOGIN 时间戳窗口
  quint32 maxFrameBody = kMaxBodyLength;
  int chunkWindow = 16;             // 一次 CHUNK_REQ 请求的片数（1 ~ 16）
  int chunkWindowTimeoutMs = 10000; // 一个窗口等不齐时，过多久重新请求
  int chunkRetryLimit = 3;          // 同一片哈希连续不符几次就中止并告警
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

// 灰度发布参数（设计 4.2 节），配置 [rollout] 段可覆盖。
struct RolloutParams {
  int observeMs = 30000;     // 金丝雀全部成功后的观察期，期间没有失败和告警才进入“待确认全量”
  int concurrency = 5;       // 新建发布时“同时推送台数”的默认值（设计里的并发上限 K）
  int maxFailurePct = 20;    // 全量阶段失败台数超过全量目标的这个百分比，发布自动暂停
};

struct ServerConfig {
  QHostAddress listenAddress;
  quint16 listenPort = 0;
  int maxConnections = 200;
  int maxConnectionsPerIp = 5;
  QString dbFile;  // SQLite 数据库文件（设备注册表、账号表、固件表、发布表、审计日志表）
  // 审计日志检查点文件：记下审计哈希链最新的哈希（设计第 13 章）。不配置时用“数据库文件名.audit-checkpoint”
  QString auditCheckpointFile;
  // 固件库目录：导入的 .fwpkg 检查通过后以“包 ID.fwpkg”为名存放在这里，下发时从这里读分片。
  QString firmwareDir;
  // 固件签名公钥（FSK 公钥，PEM）和它的指纹，含义与 ClientConfig 里的同名项相同：
  // 服务端导入固件时用这把公钥验签，指纹对不上就不启动。
  QString fskPubFile;
  QString fskPubSha256;
  // 设备登录失败锁定（设计第 14 节）：windowS 秒内失败 limit 次，锁定 lockS 秒
  int loginFailLimit = 5;
  int loginFailWindowS = 300;
  int loginLockS = 600;
  QString logLevel = QStringLiteral("INFO");
  // 运行日志文件：目录取 [server] log_dir，不配置时为数据库文件所在目录下的 logs/；轮转规则取 [log]
  LogFileParams logFile;
  ProtocolParams protocol;
  RolloutParams rollout;
  TlsConfig tls;
};

struct ClientConfig {
  QString serverHost;
  quint16 serverPort = 0;
  QString deviceId;
  QString model;
  // 设备数据目录：模拟 Flash 的 slot_a/、slot_b/、boot.json 和下载目录 download/ 都在这里（设计 5.2 节）
  QString dataDir;
  // 固件签名公钥（FSK 公钥，PEM）的位置和它的指纹（公钥 DER 的 SHA-256，64 个十六进制字符）。
  // 公钥不是秘密，可以放在文件里；指纹由部署人员按 fsk-init 显示的值填写，
  // 启动时两者对不上就不运行，防止装错公钥（设计 11.3 节）。
  QString fskPubFile;
  QString fskPubSha256;
  // 模拟重启要“黑屏”多久（毫秒）。只影响演示时 REBOOTING 状态停留的时间。
  int rebootDelayMs = 2000;
  QString logLevel = QStringLiteral("INFO");
  // 运行日志文件：目录固定为设备数据目录下的 logs/（设计 5.2 节），轮转规则取 [log]
  LogFileParams logFile;
  ProtocolParams protocol;
  TlsConfig tls;
};

// max_frame_body 的下限：一帧 CHUNK_DATA 是 24 字节头加一片 64 KB 数据（协议 5.6 节），
// 帧长上限比它还小的话，分片根本发不出去。
inline constexpr quint32 kMinFrameBody = 24 + 65536;

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
