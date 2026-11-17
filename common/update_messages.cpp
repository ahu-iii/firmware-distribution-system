#include "common/update_messages.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QtEndian>
#include <limits>

#include "common/manifest.h"

namespace fwds {

namespace {

// 读一个 JSON 字符串字段，字段不存在或不是字符串返回 false。
bool readString(const QJsonObject& obj, const char* key, QString* out) {
  const QJsonValue value = obj.value(QLatin1String(key));
  if (!value.isString()) return false;
  *out = value.toString();
  return true;
}

// 读一个 JSON 整数字段。JSON 的数字是浮点数，这里要求它正好是 [min, max] 之内的整数，
// 1.5、-1、1e300 这样的值直接拒绝，不会被悄悄截断成别的数。
bool readInteger(const QJsonObject& obj, const char* key, qint64 min, qint64 max, qint64* out) {
  const QJsonValue value = obj.value(QLatin1String(key));
  const double number = value.toDouble();
  if (!value.isDouble() || number < static_cast<double>(min) || number > static_cast<double>(max) ||
      number != static_cast<double>(static_cast<qint64>(number))) {
    return false;
  }
  *out = static_cast<qint64>(number);
  return true;
}

// 消息体必须是一个 JSON 对象。
bool parseObject(const QByteArray& body, QJsonObject* out) {
  const QJsonDocument doc = QJsonDocument::fromJson(body);
  if (!doc.isObject()) return false;
  *out = doc.object();
  return true;
}

// 发布号的取值范围：JSON 数字能精确表示的整数（2^53 以内）。
constexpr qint64 kMaxReleaseId = 9007199254740992LL;

}  // namespace

QByteArray packageIdToBytes(const QString& pkgId) {
  // \A … \z 表示整个字符串从头到尾，末尾多一个换行也不行
  static const QRegularExpression pattern(QStringLiteral(
      "\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z"));
  if (!pattern.match(pkgId).hasMatch()) return QByteArray();
  // 去掉 4 个连字符剩 32 个十六进制字符，正好 16 字节
  return QByteArray::fromHex(QString(pkgId).remove(QLatin1Char('-')).toLatin1());
}

QString packageIdFromBytes(const QByteArray& bytes) {
  if (bytes.size() != kPackageIdBytes) return QString();
  QString hex = QString::fromLatin1(bytes.toHex());
  // 按 8-4-4-4-12 插回连字符（从后往前插，前面的位置不受影响）
  hex.insert(20, QLatin1Char('-'));
  hex.insert(16, QLatin1Char('-'));
  hex.insert(12, QLatin1Char('-'));
  hex.insert(8, QLatin1Char('-'));
  return hex;
}

QByteArray encodeUpdateNotify(const UpdateNotify& notify) {
  QJsonObject obj;
  obj.insert(QStringLiteral("device_id"), notify.deviceId);
  obj.insert(QStringLiteral("release_id"), notify.releaseId);
  obj.insert(QStringLiteral("pkg_id"), notify.pkgId);
  obj.insert(QStringLiteral("manifest"), QString::fromLatin1(notify.manifestRaw.toBase64()));
  obj.insert(QStringLiteral("manifest_sig"), QString::fromLatin1(notify.signature.toBase64()));
  return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

bool parseUpdateNotify(const QByteArray& body, UpdateNotify* out) {
  QJsonObject obj;
  QString manifestBase64;
  QString signatureBase64;
  UpdateNotify notify;
  if (!parseObject(body, &obj) ||
      !readString(obj, "device_id", &notify.deviceId) ||
      !readInteger(obj, "release_id", 0, kMaxReleaseId, &notify.releaseId) ||
      !readString(obj, "pkg_id", &notify.pkgId) ||
      !readString(obj, "manifest", &manifestBase64) ||
      !readString(obj, "manifest_sig", &signatureBase64)) {
    return false;
  }
  if (packageIdToBytes(notify.pkgId).isEmpty()) return false;

  // Base64 里混进了非法字符就整条拒绝，不做“尽量解码”
  const auto manifest = QByteArray::fromBase64Encoding(manifestBase64.toLatin1(),
                                                       QByteArray::AbortOnBase64DecodingErrors);
  const auto signature = QByteArray::fromBase64Encoding(signatureBase64.toLatin1(),
                                                        QByteArray::AbortOnBase64DecodingErrors);
  if (!manifest || !signature) return false;
  notify.manifestRaw = *manifest;
  notify.signature = *signature;
  if (notify.manifestRaw.isEmpty() || notify.manifestRaw.size() > kMaxManifestSize) return false;

  *out = notify;
  return true;
}

QByteArray encodeUpdateCancel(const UpdateCancel& cancel) {
  QJsonObject obj;
  obj.insert(QStringLiteral("device_id"), cancel.deviceId);
  obj.insert(QStringLiteral("release_id"), cancel.releaseId);
  obj.insert(QStringLiteral("pkg_id"), cancel.pkgId);
  obj.insert(QStringLiteral("reason"), cancel.reason);
  return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

bool parseUpdateCancel(const QByteArray& body, UpdateCancel* out) {
  QJsonObject obj;
  UpdateCancel cancel;
  if (!parseObject(body, &obj) ||
      !readString(obj, "device_id", &cancel.deviceId) ||
      !readInteger(obj, "release_id", 0, kMaxReleaseId, &cancel.releaseId) ||
      !readString(obj, "pkg_id", &cancel.pkgId) ||
      !readString(obj, "reason", &cancel.reason)) {
    return false;
  }
  if (packageIdToBytes(cancel.pkgId).isEmpty()) return false;
  *out = cancel;
  return true;
}

QByteArray encodeChunkRequest(const ChunkRequest& request) {
  QJsonObject obj;
  obj.insert(QStringLiteral("pkg_id"), request.pkgId);
  obj.insert(QStringLiteral("from_index"), request.fromIndex);
  obj.insert(QStringLiteral("count"), request.count);
  return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

bool parseChunkRequest(const QByteArray& body, ChunkRequest* out) {
  QJsonObject obj;
  ChunkRequest request;
  qint64 fromIndex = 0;
  qint64 count = 0;
  const qint64 intMax = std::numeric_limits<int>::max();
  if (!parseObject(body, &obj) ||
      !readString(obj, "pkg_id", &request.pkgId) ||
      !readInteger(obj, "from_index", 0, intMax, &fromIndex) ||
      !readInteger(obj, "count", 0, intMax, &count)) {
    return false;
  }
  if (packageIdToBytes(request.pkgId).isEmpty()) return false;
  request.fromIndex = static_cast<int>(fromIndex);
  request.count = static_cast<int>(count);
  *out = request;
  return true;
}

QByteArray encodeChunkData(const QString& pkgId, int index, const QByteArray& data) {
  const QByteArray idBytes = packageIdToBytes(pkgId);
  if (idBytes.isEmpty() || index < 0 || data.size() > kChunkSize) return QByteArray();

  QByteArray body;
  body.reserve(kChunkDataHeaderSize + data.size());
  body.append(idBytes);
  // 两个 4 字节整数按大端（网络字节序）写入
  char number[4];
  qToBigEndian<quint32>(static_cast<quint32>(index), number);
  body.append(number, 4);
  qToBigEndian<quint32>(static_cast<quint32>(data.size()), number);
  body.append(number, 4);
  body.append(data);
  return body;
}

bool parseChunkData(const QByteArray& body, ChunkData* out) {
  // 第一步：头不完整就不往下读
  if (body.size() < kChunkDataHeaderSize) return false;

  const quint32 index = qFromBigEndian<quint32>(body.constData() + kPackageIdBytes);
  const quint32 dataLen = qFromBigEndian<quint32>(body.constData() + kPackageIdBytes + 4);
  // 第二步：先核对 data_len，再按它取数据。
  // data_len 来自对端，不能直接拿来用：它不能超过一片的大小，并且必须和实际收到的字节数对得上
  if (dataLen > static_cast<quint32>(kChunkSize)) return false;
  if (static_cast<qint64>(kChunkDataHeaderSize) + dataLen != body.size()) return false;
  if (index > static_cast<quint32>(std::numeric_limits<int>::max())) return false;

  out->pkgId = packageIdFromBytes(body.left(kPackageIdBytes));
  out->index = static_cast<int>(index);
  out->data = body.mid(kChunkDataHeaderSize);
  return true;
}

}  // namespace fwds
