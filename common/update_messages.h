// 升级相关消息体的编码和解析（协议文档 5.3 ~ 5.6 节）：
//   HEARTBEAT                      设备 → 服务端，JSON（服务端检查格式）
//   UPDATE_NOTIFY / UPDATE_CANCEL  服务端 → 设备，JSON
//   CHUNK_REQ                      设备 → 服务端，JSON
//   CHUNK_DATA                     服务端 → 设备，二进制
// 两端共用同一份代码，一端编码、另一端解析，格式不会各写各的。
// 这里只检查“格式对不对”；“这个包是不是下发给这台设备的”“下标有没有越界”由业务层判断。
#pragma once

#include <QByteArray>
#include <QString>

namespace fwds {

inline constexpr int kPackageIdBytes = 16;        // pkg_id（UUID）的二进制长度
inline constexpr int kChunkDataHeaderSize = 24;   // CHUNK_DATA 头：pkg_id 16 + chunk_index 4 + data_len 4
inline constexpr int kMaxChunkWindow = 16;        // 一次 CHUNK_REQ 最多请求的片数

// 包 ID 在 JSON 里是 "8-4-4-4-12" 的小写 UUID 字符串，在 CHUNK_DATA 里是 16 个字节。
// 字符串格式不对时 packageIdToBytes 返回空数组。
QByteArray packageIdToBytes(const QString& pkgId);
QString packageIdFromBytes(const QByteArray& bytes);

// ---- HEARTBEAT（0x10）----
struct HeartbeatStatus {
  QString state;      // 设备当前的升级状态，如 IDLE、DOWNLOADING，最长 32 个字符
  int progress = 0;   // 当前阶段的进度百分比，-1 表示没有
  qint64 uptime = 0;  // 设备程序已运行的秒数
};
// 三个字段齐全、类型正确、取值在范围内才返回 true（协议 5.3 节）。
// 不合格的心跳服务端回复 1005 并丢弃：不应答、不算作一次心跳。
bool parseHeartbeat(const QByteArray& body, HeartbeatStatus* out);

// ---- UPDATE_NOTIFY（0x20）----
struct UpdateNotify {
  QString deviceId;         // 目标设备。设备收到后先确认是发给自己的
  qint64 releaseId = 0;     // 发布号
  QString pkgId;
  QByteArray manifestRaw;   // manifest.json 原始字节，原样转发
  QByteArray signature;     // FSK 对 manifestRaw 的签名
};
QByteArray encodeUpdateNotify(const UpdateNotify& notify);
// 注意：这里只把字段取出来，不验签。manifestRaw 在验签之前不可信，不能解析。
bool parseUpdateNotify(const QByteArray& body, UpdateNotify* out);

// ---- UPDATE_CANCEL（0x21）----
struct UpdateCancel {
  QString deviceId;
  qint64 releaseId = 0;
  QString pkgId;
  QString reason;
};
QByteArray encodeUpdateCancel(const UpdateCancel& cancel);
bool parseUpdateCancel(const QByteArray& body, UpdateCancel* out);

// ---- CHUNK_REQ（0x22）----
struct ChunkRequest {
  QString pkgId;
  int fromIndex = 0;  // 第一个要的分片，从 0 开始
  int count = 0;      // 连续要几片
};
QByteArray encodeChunkRequest(const ChunkRequest& request);
// 字段齐全、pkg_id 格式正确、两个数是非负整数才返回 true。
bool parseChunkRequest(const QByteArray& body, ChunkRequest* out);

// ---- CHUNK_DATA（0x23）----
struct ChunkData {
  QString pkgId;
  int index = 0;
  QByteArray data;
};
// pkgId 格式不对或 data 超过一片的大小时返回空数组。
QByteArray encodeChunkData(const QString& pkgId, int index, const QByteArray& data);
// 先核对长度再取数据：消息体至少 24 字节，data_len 不超过一片的大小，
// 并且 24 + data_len 必须正好等于消息体长度（协议 5.6 节）。
bool parseChunkData(const QByteArray& body, ChunkData* out);

}  // namespace fwds
