// manifest 字段、序列化和解析的单元测试（协议文档 7.1 节）。
// 版本号比较是防降级判定（UT-08）要用到的基础。
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <gtest/gtest.h>

#include "common/crypto/sha256.h"
#include "common/manifest.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

namespace {

// 一份合法 manifest 的 JSON 对象，各用例在它上面改一个字段再解析。
QJsonObject validObject() {
  const Manifest manifest = manifestFor(randomBytes(kChunkSize + 100));
  return QJsonDocument::fromJson(serializeManifest(manifest)).object();
}

bool parses(const QJsonObject& obj) {
  Manifest manifest;
  QString error;
  return parseManifest(QJsonDocument(obj).toJson(QJsonDocument::Compact), &manifest, &error);
}

// 把 key 改成 value 之后是否还能解析。
bool parsesWith(const char* key, const QJsonValue& value) {
  QJsonObject obj = validObject();
  obj.insert(QLatin1String(key), value);
  return parses(obj);
}

}  // namespace

// ---------- 版本号 ----------

TEST(FirmwareVersionTest, ParsesThreeNumericParts) {
  FirmwareVersion v;
  ASSERT_TRUE(parseFirmwareVersion(QStringLiteral("2.10.3"), &v));
  EXPECT_EQ(v.major, 2);
  EXPECT_EQ(v.minor, 10);
  EXPECT_EQ(v.patch, 3);
  EXPECT_TRUE(parseFirmwareVersion(QStringLiteral("0.0.0"), &v));
  EXPECT_TRUE(parseFirmwareVersion(QStringLiteral("9999.9999.9999"), &v));
}

TEST(FirmwareVersionTest, RejectsMalformedText) {
  FirmwareVersion v;
  for (const char* text : {"", "2", "2.1", "2.1.0.4", "2.1.x", "v2.1.0", "2.1.0 ", " 2.1.0", "-1.0.0",
                           "+2.1.0", "02.1.0", "2.1.00", "10000.0.0", "2..0", "2.1.0\n", "２.1.0"}) {
    EXPECT_FALSE(parseFirmwareVersion(QString::fromUtf8(text), &v)) << text;
  }
}

// 按数值比较，不是按字符串比较：2.10.0 比 2.9.0 新
TEST(FirmwareVersionTest, ComparesNumerically) {
  const auto cmp = [](const char* a, const char* b) {
    FirmwareVersion va;
    FirmwareVersion vb;
    EXPECT_TRUE(parseFirmwareVersion(QString::fromLatin1(a), &va));
    EXPECT_TRUE(parseFirmwareVersion(QString::fromLatin1(b), &vb));
    return compareFirmwareVersion(va, vb);
  };
  EXPECT_LT(cmp("1.9.0", "2.0.0"), 0);
  EXPECT_EQ(cmp("2.0.0", "2.0.0"), 0);
  EXPECT_GT(cmp("2.1.0", "2.0.0"), 0);
  EXPECT_GT(cmp("2.10.0", "2.9.0"), 0);
  EXPECT_LT(cmp("2.0.9", "2.1.0"), 0);
  EXPECT_GT(cmp("2.0.1", "2.0.0"), 0);
}

// ---------- 分片划分 ----------

TEST(ManifestTest, ChunkCountAndLastChunkLength) {
  EXPECT_EQ(chunkCountFor(1), 1);
  EXPECT_EQ(chunkCountFor(kChunkSize), 1);
  EXPECT_EQ(chunkCountFor(kChunkSize + 1), 2);
  EXPECT_EQ(chunkCountFor(kMaxImageSize), 4096);

  const Manifest m = manifestFor(randomBytes(2 * kChunkSize + 100));
  EXPECT_EQ(m.imageSize, 2 * kChunkSize + 100);
  EXPECT_EQ(m.chunkCount, 3);
  EXPECT_EQ(m.chunkLength(0), kChunkSize);
  EXPECT_EQ(m.chunkLength(1), kChunkSize);
  EXPECT_EQ(m.chunkLength(2), 100);  // 最后一片不满
  EXPECT_EQ(m.chunkLength(-1), -1);
  EXPECT_EQ(m.chunkLength(3), -1);

  // 正好是整片的倍数时，最后一片也是满的
  EXPECT_EQ(manifestFor(randomBytes(2 * kChunkSize)).chunkLength(1), kChunkSize);
}

// ---------- 序列化与解析 ----------

TEST(ManifestTest, SerializeParseRoundTrip) {
  const QByteArray image = randomBytes(3 * kChunkSize + 7);
  const Manifest original = manifestFor(image);
  const QByteArray raw = serializeManifest(original);

  Manifest parsed;
  QString error;
  ASSERT_TRUE(parseManifest(raw, &parsed, &error)) << error.toStdString();
  EXPECT_EQ(parsed.format, kManifestFormat);
  EXPECT_EQ(parsed.pkgId, original.pkgId);
  EXPECT_EQ(parsed.deviceModel, QStringLiteral("PLC-X200"));
  EXPECT_EQ(parsed.version, QStringLiteral("2.1.0"));
  EXPECT_EQ(parsed.securityVersion, 5);
  EXPECT_EQ(parsed.imageSize, image.size());
  EXPECT_EQ(parsed.imageSha256, sha256(image));
  EXPECT_EQ(parsed.chunkSize, kChunkSize);
  EXPECT_EQ(parsed.chunkCount, 4);
  EXPECT_EQ(parsed.chunkSha256, original.chunkSha256);
  EXPECT_EQ(parsed.chunkSha256.at(3), sha256(image.right(7)));
  EXPECT_EQ(parsed.buildTime, original.buildTime);
  EXPECT_EQ(parsed.releaseNote, original.releaseNote);
  // 协议文档 7.1 节列出的 12 个字段都在
  EXPECT_EQ(QJsonDocument::fromJson(raw).object().size(), 12);
}

TEST(ManifestTest, RejectsNonObjectAndOversizedInput) {
  Manifest m;
  QString error;
  EXPECT_FALSE(parseManifest("", &m, &error));
  EXPECT_FALSE(parseManifest("[]", &m, &error));
  EXPECT_FALSE(parseManifest("{\"format\":1", &m, &error));
  EXPECT_FALSE(parseManifest("not json", &m, &error));
  // 超过长度上限：不交给 JSON 解析器
  EXPECT_FALSE(parseManifest(QByteArray(kMaxManifestSize + 1, ' '), &m, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("超过")));
}

// 12 个字段缺任何一个都不接受
TEST(ManifestTest, RejectsMissingField) {
  const QJsonObject valid = validObject();
  ASSERT_TRUE(parses(valid));
  for (const QString& key : valid.keys()) {
    QJsonObject obj = valid;
    obj.remove(key);
    EXPECT_FALSE(parses(obj)) << key.toStdString();
  }
}

// 类型不对：数字写成字符串、字符串写成数字、数组写成字符串
TEST(ManifestTest, RejectsWrongTypes) {
  EXPECT_FALSE(parsesWith("format", QStringLiteral("1")));
  EXPECT_FALSE(parsesWith("security_version", QStringLiteral("5")));
  EXPECT_FALSE(parsesWith("image_size", QStringLiteral("100")));
  EXPECT_FALSE(parsesWith("version", 2));
  EXPECT_FALSE(parsesWith("pkg_id", QJsonValue()));
  EXPECT_FALSE(parsesWith("chunk_sha256", QStringLiteral("abc")));
  EXPECT_FALSE(parsesWith("release_note", 0));
}

TEST(ManifestTest, RejectsOutOfRangeNumbers) {
  EXPECT_FALSE(parsesWith("format", 2));  // 不认识的格式版本
  EXPECT_FALSE(parsesWith("format", 0));
  EXPECT_FALSE(parsesWith("security_version", 0));
  EXPECT_FALSE(parsesWith("security_version", -1));
  EXPECT_FALSE(parsesWith("security_version", 5.5));  // 不是整数
  EXPECT_FALSE(parsesWith("security_version", 1e300));
  EXPECT_TRUE(parsesWith("security_version", 2147483647.0));
  EXPECT_FALSE(parsesWith("security_version", 2147483648.0));
  EXPECT_FALSE(parsesWith("image_size", 0));
  EXPECT_FALSE(parsesWith("image_size", static_cast<double>(kMaxImageSize) + 1));
  EXPECT_FALSE(parsesWith("chunk_size", 4096));  // 片大小固定
  EXPECT_FALSE(parsesWith("chunk_size", 65537));
}

TEST(ManifestTest, RejectsBadIdentifiers) {
  // pkg_id 以后会出现在文件名里，带路径分隔符的值必须被挡住
  EXPECT_FALSE(parsesWith("pkg_id", QStringLiteral("../../etc/passwd")));
  EXPECT_FALSE(parsesWith("pkg_id", QStringLiteral("")));
  EXPECT_FALSE(parsesWith("pkg_id", QStringLiteral("6F1C2B0E-8D7A-4A51-9B3E-2C4F6D8E0A11")));  // 大写
  EXPECT_FALSE(parsesWith("pkg_id", QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a1")));   // 少一位
  EXPECT_TRUE(parsesWith("pkg_id", QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a11")));

  EXPECT_FALSE(parsesWith("device_model", QStringLiteral("")));
  EXPECT_FALSE(parsesWith("device_model", QStringLiteral("PLC X200")));
  EXPECT_FALSE(parsesWith("device_model", QStringLiteral("PLC/X200")));
  // 末尾带换行符的值也不能混进来
  EXPECT_FALSE(parsesWith("device_model", QStringLiteral("PLC-X200\n")));
  EXPECT_FALSE(parsesWith("pkg_id", QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a11\n")));
  EXPECT_FALSE(parsesWith("image_sha256", QString(64, QLatin1Char('a')) + QLatin1Char('\n')));
  EXPECT_FALSE(parsesWith("device_model", QString(65, QLatin1Char('a'))));

  EXPECT_FALSE(parsesWith("version", QStringLiteral("2.1")));
  EXPECT_FALSE(parsesWith("version", QStringLiteral("latest")));
  EXPECT_FALSE(parsesWith("build_time", QStringLiteral("yesterday")));
  EXPECT_FALSE(parsesWith("release_note", QString(kMaxReleaseNoteLength + 1, QLatin1Char('n'))));
  EXPECT_TRUE(parsesWith("release_note", QString(kMaxReleaseNoteLength, QLatin1Char('n'))));
}

// 片数、哈希个数、镜像大小三者必须对得上
TEST(ManifestTest, RejectsInconsistentChunkTable) {
  // validObject 的镜像是 64 KB + 100 字节，共 2 片
  EXPECT_FALSE(parsesWith("chunk_count", 1));
  EXPECT_FALSE(parsesWith("chunk_count", 3));
  EXPECT_FALSE(parsesWith("image_size", kChunkSize));          // 这个大小只该有 1 片
  EXPECT_FALSE(parsesWith("image_size", 2 * kChunkSize + 1));  // 这个大小该有 3 片
  EXPECT_TRUE(parsesWith("image_size", 2 * kChunkSize));       // 仍是 2 片，结构上自洽

  QJsonObject obj = validObject();
  QJsonArray chunks = obj.value(QLatin1String("chunk_sha256")).toArray();
  chunks.removeLast();
  obj.insert(QLatin1String("chunk_sha256"), chunks);
  EXPECT_FALSE(parses(obj));  // 哈希少一个
}

TEST(ManifestTest, RejectsMalformedDigests) {
  const QString good(64, QLatin1Char('a'));
  EXPECT_TRUE(parsesWith("image_sha256", good));
  EXPECT_FALSE(parsesWith("image_sha256", QString(63, QLatin1Char('a'))));
  EXPECT_FALSE(parsesWith("image_sha256", QString(64, QLatin1Char('A'))));  // 必须小写
  EXPECT_FALSE(parsesWith("image_sha256", QString(64, QLatin1Char('g'))));

  for (const QJsonValue& bad : {QJsonValue(QString(62, QLatin1Char('a'))), QJsonValue(7), QJsonValue()}) {
    QJsonObject obj = validObject();
    QJsonArray chunks = obj.value(QLatin1String("chunk_sha256")).toArray();
    chunks.replace(1, bad);
    obj.insert(QLatin1String("chunk_sha256"), chunks);
    EXPECT_FALSE(parses(obj));
  }
}

// 解析失败时不改动调用方的输出对象
TEST(ManifestTest, OutputUntouchedOnFailure) {
  Manifest m;
  m.pkgId = QStringLiteral("before");
  QString error;
  EXPECT_FALSE(parseManifest("{}", &m, &error));
  EXPECT_EQ(m.pkgId, QStringLiteral("before"));
  EXPECT_FALSE(error.isEmpty());
}
