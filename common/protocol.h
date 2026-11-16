// FWDS 协议常量：帧格式、消息类型、错误码。
// 数值与 docs/通信协议文档.md 第 3、4、6 节一一对应，两端共用。
#pragma once

#include <QByteArray>
#include <QtGlobal>

namespace fwds {

// ---- 帧头（协议 3.1 节）----
inline constexpr quint8 kMagic0 = 0x46;          // 'F'
inline constexpr quint8 kMagic1 = 0x57;          // 'W'
inline constexpr quint8 kProtocolVersion = 0x02;
inline constexpr int kHeaderSize = 16;           // Magic 2 + Ver 1 + Type 1 + Seq 8 + Length 4
inline constexpr quint32 kMaxBodyLength = 1048576;  // Body 上限 1 MB
inline constexpr quint64 kFirstSeq = 1;          // 每个方向第一帧的序号

// ---- 消息类型（协议第 4 节）----
enum class MsgType : quint8 {
  Login = 0x01,
  LoginResult = 0x02,
  Heartbeat = 0x10,
  HeartbeatAck = 0x11,
  UpdateNotify = 0x20,
  UpdateCancel = 0x21,
  ChunkReq = 0x22,
  ChunkData = 0x23,
  Progress = 0x30,
  Result = 0x31,
  Alert = 0x32,
  Bye = 0x7E,
  Error = 0x7F,
};

// ---- 错误码（协议 6.2 节）----
enum class ErrorCode : int {
  Ok = 0,
  BadMagic = 1001,
  BadVersion = 1002,
  FrameTooLarge = 1003,
  UnexpectedMessage = 1004,
  BadJson = 1005,
  SeqError = 1007,
  LoginTimeout = 2001,
  TsOutOfWindow = 2002,
  IdCertMismatch = 2003,
  DeviceAuthFailed = 2005,
  LicenseInvalid = 2006,
  DeviceLocked = 2007,
  TooManyConnections = 2008,
  SigInvalid = 3001,
  ModelMismatch = 3002,
  RollbackAttempt = 3003,
  ChunkTampered = 3004,
  ImageTampered = 3005,
  WriteFailed = 3006,
  SelftestFailed = 3007,
  BootFailed = 3008,
  PkgNotFound = 3009,
  ChunkOutOfRange = 3010,
  DiskFull = 3011,
  Cancelled = 3012,
  Busy = 3013,
  ManifestInvalid = 3014,
};

// 一帧：帧头里上层关心的字段加消息体。
struct Frame {
  quint8 type = 0;
  quint64 seq = 0;
  QByteArray body;
};

// 该错误码是否要求发送 ERROR 后关闭连接。
// 1xxx、2xxx 关闭；1005 BAD_JSON 和 3xxx 不关闭（协议 5.8、6.2 节）。
bool closesConnection(int code);

// 消息类型名，只用于日志；未知类型返回 "UNKNOWN"。
const char* msgTypeName(quint8 type);

// 错误码的英文名（写进 ERROR 帧的 message 和日志）。
const char* errorName(ErrorCode code);

}  // namespace fwds
