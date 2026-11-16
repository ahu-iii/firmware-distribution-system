#include "common/manifest.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

#include "common/crypto/sha256.h"

namespace fwds {

namespace {

// 下面几个正则都用 \A … \z 表示“整个字符串从头到尾”。
// 不用 ^ … $：$ 在字符串末尾的换行符之前也能匹配，"2.1.0\n" 会被当成合法值放进来。

// 64 个小写十六进制字符 → 32 字节摘要。格式不对返回空数组。
QByteArray digestFromHex(const QString& hex) {
  static const QRegularExpression pattern(QStringLiteral("\\A[0-9a-f]{64}\\z"));
  if (!pattern.match(hex).hasMatch()) return QByteArray();
  return QByteArray::fromHex(hex.toLatin1());
}

QString digestToHex(const QByteArray& digest) { return QString::fromLatin1(digest.toHex()); }

// 读一个字符串字段。字段不存在或不是字符串返回 false。
bool readString(const QJsonObject& obj, const char* key, QString* out, QString* error) {
  const QJsonValue value = obj.value(QLatin1String(key));
  if (!value.isString()) {
    *error = QStringLiteral("manifest 缺少字符串字段 %1").arg(QLatin1String(key));
    return false;
  }
  *out = value.toString();
  return true;
}

// 读一个整数字段。JSON 里数字都是浮点数，这里要求它正好是整数并且在 [min, max] 之内，
// 像 1.5、1e300、-1 这样的值在这一步就被挡住，不会被悄悄截断成别的数。
bool readInteger(const QJsonObject& obj, const char* key, qint64 min, qint64 max, qint64* out,
                 QString* error) {
  const QJsonValue value = obj.value(QLatin1String(key));
  const double number = value.toDouble();
  if (!value.isDouble() || number < static_cast<double>(min) || number > static_cast<double>(max) ||
      number != static_cast<double>(static_cast<qint64>(number))) {
    *error = QStringLiteral("manifest 字段 %1 不是允许范围内的整数").arg(QLatin1String(key));
    return false;
  }
  *out = static_cast<qint64>(number);
  return true;
}

}  // namespace

bool parseFirmwareVersion(const QString& text, FirmwareVersion* out) {
  // 每一段：单独一个 0，或者不以 0 开头的 1 ~ 4 位数字
  static const QRegularExpression pattern(
      QStringLiteral("\\A(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})\\z"));
  const QRegularExpressionMatch match = pattern.match(text);
  if (!match.hasMatch()) return false;
  out->major = match.captured(1).toInt();
  out->minor = match.captured(2).toInt();
  out->patch = match.captured(3).toInt();
  return true;
}

int compareFirmwareVersion(const FirmwareVersion& a, const FirmwareVersion& b) {
  // 先比主版本，相同再比次版本，再相同比修订号
  if (a.major != b.major) return a.major < b.major ? -1 : 1;
  if (a.minor != b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch != b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

qint64 Manifest::chunkLength(int index) const {
  if (index < 0 || index >= chunkCount) return -1;
  if (index < chunkCount - 1) return chunkSize;
  // 最后一片 = 总长度减去前面所有整片
  return imageSize - static_cast<qint64>(chunkCount - 1) * chunkSize;
}

int chunkCountFor(qint64 imageSize) {
  return static_cast<int>((imageSize + kChunkSize - 1) / kChunkSize);
}

bool checkManifest(const Manifest& m, QString* error) {
  static const QRegularExpression uuidPattern(
      QStringLiteral("\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z"));
  static const QRegularExpression modelPattern(QStringLiteral("\\A[A-Za-z0-9._-]{1,64}\\z"));

  if (m.format != kManifestFormat) {
    *error = QStringLiteral("不支持的 manifest 格式版本 %1").arg(m.format);
    return false;
  }
  if (!uuidPattern.match(m.pkgId).hasMatch()) {
    *error = QStringLiteral("pkg_id 不是小写 UUID");
    return false;
  }
  if (!modelPattern.match(m.deviceModel).hasMatch()) {
    *error = QStringLiteral("device_model 只能由字母、数字、点、下划线、连字符组成，1 ~ 64 个字符");
    return false;
  }
  FirmwareVersion version;
  if (!parseFirmwareVersion(m.version, &version)) {
    *error = QStringLiteral("version 必须是 主.次.修订 三段数字");
    return false;
  }
  if (m.securityVersion < 1) {
    *error = QStringLiteral("security_version 必须是正整数");
    return false;
  }
  if (m.imageSize < 1 || m.imageSize > kMaxImageSize) {
    *error = QStringLiteral("image_size 必须在 1 字节 ~ %1 MB 之间").arg(kMaxImageSize / (1024 * 1024));
    return false;
  }
  if (m.chunkSize != kChunkSize) {
    *error = QStringLiteral("chunk_size 必须是 %1").arg(kChunkSize);
    return false;
  }
  // 片数不是独立的输入，必须能由镜像大小算出来；哈希个数又必须等于片数
  if (m.chunkCount != chunkCountFor(m.imageSize) || m.chunkSha256.size() != m.chunkCount) {
    *error = QStringLiteral("chunk_count、chunk_sha256 的个数与 image_size 不一致");
    return false;
  }
  if (m.imageSha256.size() != kSha256Size) {
    *error = QStringLiteral("image_sha256 不是 SHA-256 摘要");
    return false;
  }
  for (const QByteArray& digest : m.chunkSha256) {
    if (digest.size() != kSha256Size) {
      *error = QStringLiteral("chunk_sha256 里有不是 SHA-256 摘要的项");
      return false;
    }
  }
  if (!QDateTime::fromString(m.buildTime, Qt::ISODate).isValid()) {
    *error = QStringLiteral("build_time 不是 ISO 8601 时间");
    return false;
  }
  if (m.releaseNote.size() > kMaxReleaseNoteLength) {
    *error = QStringLiteral("release_note 超过 %1 个字符").arg(kMaxReleaseNoteLength);
    return false;
  }
  return true;
}

QByteArray serializeManifest(const Manifest& m) {
  QJsonArray chunks;
  for (const QByteArray& digest : m.chunkSha256) chunks.append(digestToHex(digest));

  QJsonObject obj;
  obj.insert(QStringLiteral("format"), m.format);
  obj.insert(QStringLiteral("pkg_id"), m.pkgId);
  obj.insert(QStringLiteral("device_model"), m.deviceModel);
  obj.insert(QStringLiteral("version"), m.version);
  obj.insert(QStringLiteral("security_version"), m.securityVersion);
  obj.insert(QStringLiteral("image_size"), m.imageSize);
  obj.insert(QStringLiteral("image_sha256"), digestToHex(m.imageSha256));
  obj.insert(QStringLiteral("chunk_size"), m.chunkSize);
  obj.insert(QStringLiteral("chunk_count"), m.chunkCount);
  obj.insert(QStringLiteral("chunk_sha256"), chunks);
  obj.insert(QStringLiteral("build_time"), m.buildTime);
  obj.insert(QStringLiteral("release_note"), m.releaseNote);
  return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

bool parseManifest(const QByteArray& raw, Manifest* out, QString* error) {
  // 长度先于解析检查：超长的输入不交给 JSON 解析器
  if (raw.size() > kMaxManifestSize) {
    *error = QStringLiteral("manifest 超过 %1 KB").arg(kMaxManifestSize / 1024);
    return false;
  }
  QJsonParseError parseError;
  const QJsonDocument doc = QJsonDocument::fromJson(raw, &parseError);
  if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
    *error = QStringLiteral("manifest 不是合法的 JSON 对象");
    return false;
  }
  const QJsonObject obj = doc.object();

  Manifest m;
  qint64 format = 0;
  qint64 securityVersion = 0;
  qint64 chunkSize = 0;
  qint64 chunkCount = 0;
  QString imageHex;
  const qint64 maxChunks = chunkCountFor(kMaxImageSize);
  if (!readInteger(obj, "format", 0, 65535, &format, error) ||
      !readString(obj, "pkg_id", &m.pkgId, error) ||
      !readString(obj, "device_model", &m.deviceModel, error) ||
      !readString(obj, "version", &m.version, error) ||
      !readInteger(obj, "security_version", 1, INT32_MAX, &securityVersion, error) ||
      !readInteger(obj, "image_size", 1, kMaxImageSize, &m.imageSize, error) ||
      !readString(obj, "image_sha256", &imageHex, error) ||
      !readInteger(obj, "chunk_size", kChunkSize, kChunkSize, &chunkSize, error) ||
      !readInteger(obj, "chunk_count", 1, maxChunks, &chunkCount, error) ||
      !readString(obj, "build_time", &m.buildTime, error) ||
      !readString(obj, "release_note", &m.releaseNote, error)) {
    return false;
  }
  m.format = static_cast<int>(format);
  m.securityVersion = static_cast<int>(securityVersion);
  m.chunkSize = static_cast<int>(chunkSize);
  m.chunkCount = static_cast<int>(chunkCount);
  m.imageSha256 = digestFromHex(imageHex);

  const QJsonValue chunks = obj.value(QLatin1String("chunk_sha256"));
  if (!chunks.isArray() || chunks.toArray().size() != m.chunkCount) {
    *error = QStringLiteral("manifest 的 chunk_sha256 不是长度为 chunk_count 的数组");
    return false;
  }
  for (const QJsonValue& item : chunks.toArray()) {
    // 不是字符串或不是 64 位十六进制时得到空数组，由下面的 checkManifest 统一拒绝
    m.chunkSha256.append(digestFromHex(item.toString()));
  }

  if (!checkManifest(m, error)) return false;
  *out = m;
  return true;
}

}  // namespace fwds
