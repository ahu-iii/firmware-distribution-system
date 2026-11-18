// 升级消息体编解码的单元测试（协议 5.4 ~ 5.6 节）。
// 重点是 CHUNK_DATA 的长度检查：data_len 来自对端，必须先核对再使用。
#include <QJsonDocument>
#include <QJsonObject>
#include <QtEndian>
#include <gtest/gtest.h>

#include "common/crypto/rand.h"
#include "common/manifest.h"
#include "common/update_messages.h"

using namespace fwds;

namespace {
const QString kPkgId = QStringLiteral("6f1c2b0e-8d7a-4a51-9b3e-2c4f6d8e0a11");
}

TEST(UpdateMessages, PackageIdRoundTrip) {
  const QByteArray bytes = packageIdToBytes(kPkgId);
  ASSERT_EQ(bytes.size(), 16);
  EXPECT_EQ(bytes.toHex(), QByteArray("6f1c2b0e8d7a4a519b3e2c4f6d8e0a11"));
  EXPECT_EQ(packageIdFromBytes(bytes), kPkgId);
}

// 包 ID 会被拼进文件名，格式不对的一律拒绝
TEST(UpdateMessages, PackageIdRejectsBadFormat) {
  EXPECT_TRUE(packageIdToBytes(QStringLiteral("")).isEmpty());
  EXPECT_TRUE(packageIdToBytes(QStringLiteral("6F1C2B0E-8D7A-4A51-9B3E-2C4F6D8E0A11")).isEmpty());
  EXPECT_TRUE(packageIdToBytes(QStringLiteral("6f1c2b0e8d7a4a519b3e2c4f6d8e0a11")).isEmpty());
  EXPECT_TRUE(packageIdToBytes(kPkgId + QLatin1Char('\n')).isEmpty());
  EXPECT_TRUE(packageIdToBytes(QStringLiteral("../../../etc/passwd-aaaa-aaaa-aaaaaaaaaaaa")).isEmpty());
  EXPECT_TRUE(packageIdFromBytes(QByteArray(15, 'x')).isEmpty());
}

TEST(UpdateMessages, UpdateNotifyRoundTrip) {
  UpdateNotify notify;
  notify.deviceId = QStringLiteral("DEV-001");
  notify.releaseId = 12;
  notify.pkgId = kPkgId;
  notify.manifestRaw = QByteArray("{\"format\":1}\x00\xff", 14);  // 原始字节要原样往返
  notify.signature = randomBytes(384);

  UpdateNotify parsed;
  ASSERT_TRUE(parseUpdateNotify(encodeUpdateNotify(notify), &parsed));
  EXPECT_EQ(parsed.deviceId, notify.deviceId);
  EXPECT_EQ(parsed.releaseId, 12);
  EXPECT_EQ(parsed.pkgId, kPkgId);
  EXPECT_EQ(parsed.manifestRaw, notify.manifestRaw);
  EXPECT_EQ(parsed.signature, notify.signature);
}

TEST(UpdateMessages, UpdateNotifyRejectsMalformed) {
  UpdateNotify notify;
  notify.deviceId = QStringLiteral("DEV-001");
  notify.releaseId = 12;
  notify.pkgId = kPkgId;
  notify.manifestRaw = QByteArray("{}");
  notify.signature = QByteArray(384, 's');
  const QJsonObject good = QJsonDocument::fromJson(encodeUpdateNotify(notify)).object();
  const auto encode = [](const QJsonObject& o) { return QJsonDocument(o).toJson(); };

  UpdateNotify out;
  EXPECT_FALSE(parseUpdateNotify("not json", &out));
  EXPECT_FALSE(parseUpdateNotify("[1,2]", &out));
  for (const char* key : {"device_id", "release_id", "pkg_id", "manifest", "manifest_sig"}) {
    QJsonObject missing = good;
    missing.remove(QLatin1String(key));
    EXPECT_FALSE(parseUpdateNotify(encode(missing), &out)) << key;
  }
  QJsonObject badBase64 = good;
  badBase64.insert(QStringLiteral("manifest"), QStringLiteral("***not base64***"));
  EXPECT_FALSE(parseUpdateNotify(encode(badBase64), &out));
  QJsonObject fraction = good;
  fraction.insert(QStringLiteral("release_id"), 1.5);
  EXPECT_FALSE(parseUpdateNotify(encode(fraction), &out));
  QJsonObject badPkg = good;
  badPkg.insert(QStringLiteral("pkg_id"), QStringLiteral("../evil"));
  EXPECT_FALSE(parseUpdateNotify(encode(badPkg), &out));
  // manifest 超过 512 KB 上限
  QJsonObject huge = good;
  huge.insert(QStringLiteral("manifest"),
              QString::fromLatin1(QByteArray(kMaxManifestSize + 1, 'a').toBase64()));
  EXPECT_FALSE(parseUpdateNotify(encode(huge), &out));
}

TEST(UpdateMessages, UpdateCancelRoundTrip) {
  UpdateCancel cancel{QStringLiteral("DEV-001"), 12, kPkgId, QStringLiteral("emergency_stop")};
  UpdateCancel parsed;
  ASSERT_TRUE(parseUpdateCancel(encodeUpdateCancel(cancel), &parsed));
  EXPECT_EQ(parsed.deviceId, cancel.deviceId);
  EXPECT_EQ(parsed.pkgId, kPkgId);
  EXPECT_EQ(parsed.reason, QStringLiteral("emergency_stop"));
  EXPECT_FALSE(parseUpdateCancel("{}", &parsed));
}

TEST(UpdateMessages, ChunkRequestRoundTrip) {
  ChunkRequest parsed;
  ASSERT_TRUE(parseChunkRequest(encodeChunkRequest({kPkgId, 75, 16}), &parsed));
  EXPECT_EQ(parsed.pkgId, kPkgId);
  EXPECT_EQ(parsed.fromIndex, 75);
  EXPECT_EQ(parsed.count, 16);
}

TEST(UpdateMessages, ChunkRequestRejectsMalformed) {
  ChunkRequest out;
  EXPECT_FALSE(parseChunkRequest("", &out));
  EXPECT_FALSE(parseChunkRequest("{\"pkg_id\":\"x\",\"from_index\":0,\"count\":1}", &out));
  const QByteArray id = "\"pkg_id\":\"" + kPkgId.toLatin1() + "\"";
  EXPECT_FALSE(parseChunkRequest("{" + id + ",\"count\":1}", &out));                      // 缺字段
  EXPECT_FALSE(parseChunkRequest("{" + id + ",\"from_index\":-1,\"count\":1}", &out));    // 负数
  EXPECT_FALSE(parseChunkRequest("{" + id + ",\"from_index\":0.5,\"count\":1}", &out));   // 小数
  EXPECT_FALSE(parseChunkRequest("{" + id + ",\"from_index\":1e300,\"count\":1}", &out)); // 超大
  EXPECT_FALSE(parseChunkRequest("{" + id + ",\"from_index\":\"0\",\"count\":1}", &out)); // 类型不对
}

TEST(UpdateMessages, ChunkDataRoundTrip) {
  const QByteArray data = randomBytes(kChunkSize);
  const QByteArray body = encodeChunkData(kPkgId, 159, data);
  ASSERT_EQ(body.size(), kChunkDataHeaderSize + kChunkSize);
  // 线上格式：pkg_id 16 字节 + 大端 chunk_index + 大端 data_len
  EXPECT_EQ(body.left(16), packageIdToBytes(kPkgId));
  EXPECT_EQ(qFromBigEndian<quint32>(body.constData() + 16), 159u);
  EXPECT_EQ(qFromBigEndian<quint32>(body.constData() + 20), 65536u);

  ChunkData parsed;
  ASSERT_TRUE(parseChunkData(body, &parsed));
  EXPECT_EQ(parsed.pkgId, kPkgId);
  EXPECT_EQ(parsed.index, 159);
  EXPECT_EQ(parsed.data, data);

  // 最后一片可以不满，甚至只有 1 字节
  ASSERT_TRUE(parseChunkData(encodeChunkData(kPkgId, 0, QByteArray(1, 'z')), &parsed));
  EXPECT_EQ(parsed.data, QByteArray(1, 'z'));
}

TEST(UpdateMessages, ChunkDataEncodeRejectsBadInput) {
  EXPECT_TRUE(encodeChunkData(QStringLiteral("bad"), 0, QByteArray(10, 'a')).isEmpty());
  EXPECT_TRUE(encodeChunkData(kPkgId, -1, QByteArray(10, 'a')).isEmpty());
  EXPECT_TRUE(encodeChunkData(kPkgId, 0, QByteArray(kChunkSize + 1, 'a')).isEmpty());
}

// data_len 与实际长度不符、超过一片大小、头不完整，都必须拒绝
TEST(UpdateMessages, ChunkDataLengthIsCheckedBeforeUse) {
  const QByteArray good = encodeChunkData(kPkgId, 3, QByteArray(100, 'a'));
  ChunkData out;
  out.index = -7;

  EXPECT_FALSE(parseChunkData(QByteArray(), &out));
  EXPECT_FALSE(parseChunkData(good.left(kChunkDataHeaderSize - 1), &out));  // 头不完整
  EXPECT_FALSE(parseChunkData(good.left(good.size() - 1), &out));           // 数据比 data_len 少
  EXPECT_FALSE(parseChunkData(good + 'x', &out));                           // 数据比 data_len 多

  // data_len 写成 0xFFFFFFFF：不能按它去取数据
  QByteArray hugeLen = good;
  qToBigEndian<quint32>(0xFFFFFFFFu, hugeLen.data() + 20);
  EXPECT_FALSE(parseChunkData(hugeLen, &out));

  // data_len 和实际长度一致，但超过一片的大小
  QByteArray oversized = good.left(kChunkDataHeaderSize) + QByteArray(kChunkSize + 1, 'a');
  qToBigEndian<quint32>(static_cast<quint32>(kChunkSize + 1), oversized.data() + 20);
  EXPECT_FALSE(parseChunkData(oversized, &out));

  // chunk_index 超出 int 范围
  QByteArray hugeIndex = good;
  qToBigEndian<quint32>(0x80000000u, hugeIndex.data() + 16);
  EXPECT_FALSE(parseChunkData(hugeIndex, &out));

  EXPECT_EQ(out.index, -7);  // 失败时不改输出
}

// HEARTBEAT（协议 5.3 节）：设备实际发出的格式能解析，缺字段、类型不对、超范围的都拒绝
TEST(UpdateMessages, HeartbeatParse) {
  HeartbeatStatus s;
  ASSERT_TRUE(parseHeartbeat(R"({"state":"DOWNLOADING","progress":47,"uptime":3600})", &s));
  EXPECT_EQ(s.state, QStringLiteral("DOWNLOADING"));
  EXPECT_EQ(s.progress, 47);
  EXPECT_EQ(s.uptime, 3600);
  EXPECT_TRUE(parseHeartbeat(R"({"state":"IDLE","progress":-1,"uptime":0,"extra":1})", &s));
  for (const char* bad : {"", "null", "[]", "{}", R"({"state":"","progress":0,"uptime":0})",
                          R"({"state":"IDLE","progress":0})", R"({"state":1,"progress":0,"uptime":0})",
                          R"({"state":"IDLE","progress":-2,"uptime":0})",
                          R"({"state":"IDLE","progress":0,"uptime":-1})",
                          R"({"state":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","progress":0,"uptime":0})"}) {
    EXPECT_FALSE(parseHeartbeat(bad, &s)) << bad;
  }
}
