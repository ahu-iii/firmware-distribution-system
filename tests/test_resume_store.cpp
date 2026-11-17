// 断点位图和断点落盘的单元测试（设计 4.3 节）。对应 UT-10，以及 FT-06、FT-07 在函数一级的验证：
// 进度在盘上、重新打开能接着下；缓存被改能查出来；固件更换后旧进度作废。
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "client/storage/chunk_bitmap.h"
#include "client/storage/resume_store.h"
#include "common/security/manifest_verifier.h"
#include "test_fsk.h"

using namespace fwds;
using namespace fwds_test;

// UT-10：标记第 0、5、159 片后序列化、反序列化，位图一致，下一个缺失片为 1
TEST(ChunkBitmap, SerializeRoundTrip) {
  ChunkBitmap bitmap(160);
  bitmap.set(0);
  bitmap.set(5);
  bitmap.set(159);
  EXPECT_EQ(bitmap.doneCount(), 3);
  EXPECT_EQ(bitmap.firstMissing(), 1);

  const QByteArray bytes = bitmap.toBytes();
  ASSERT_EQ(bytes.size(), 20);  // 160 片正好 20 字节
  EXPECT_EQ(static_cast<quint8>(bytes.at(0)), 0x21);   // 第 0 位和第 5 位
  EXPECT_EQ(static_cast<quint8>(bytes.at(19)), 0x80);  // 第 159 片是最后一个字节的最高位

  ChunkBitmap restored;
  ASSERT_TRUE(ChunkBitmap::fromBytes(bytes, 160, &restored));
  EXPECT_EQ(restored.toBytes(), bytes);
  EXPECT_EQ(restored.doneCount(), 3);
  EXPECT_TRUE(restored.test(0) && restored.test(5) && restored.test(159));
  EXPECT_FALSE(restored.test(1));
  EXPECT_EQ(restored.firstMissing(), 1);
}

TEST(ChunkBitmap, SetClearAndBounds) {
  ChunkBitmap bitmap(10);
  EXPECT_FALSE(bitmap.isComplete());
  for (int i = 0; i < 10; ++i) bitmap.set(i);
  EXPECT_TRUE(bitmap.isComplete());
  EXPECT_EQ(bitmap.firstMissing(), 10);  // 全部完成时返回片数

  bitmap.set(3);  // 重复标记不重复计数
  EXPECT_EQ(bitmap.doneCount(), 10);
  bitmap.clear(3);
  bitmap.clear(3);
  EXPECT_EQ(bitmap.doneCount(), 9);
  EXPECT_EQ(bitmap.firstMissing(), 3);
  EXPECT_EQ(bitmap.firstMissing(4), 10);

  // 越界下标：读为未完成，写被忽略
  EXPECT_FALSE(bitmap.test(-1));
  EXPECT_FALSE(bitmap.test(10));
  bitmap.set(10);
  bitmap.set(-1);
  EXPECT_EQ(bitmap.doneCount(), 9);
}

// 长度不对、多出来的位被置 1 的位图不接受
TEST(ChunkBitmap, FromBytesRejectsMismatch) {
  ChunkBitmap out;
  EXPECT_FALSE(ChunkBitmap::fromBytes(QByteArray(1, '\0'), 10, &out));         // 10 片要 2 字节
  EXPECT_FALSE(ChunkBitmap::fromBytes(QByteArray(3, '\0'), 10, &out));
  EXPECT_FALSE(ChunkBitmap::fromBytes(QByteArray("\xff\xff", 2), 10, &out));   // 第 10 ~ 15 位不该有
  EXPECT_TRUE(ChunkBitmap::fromBytes(QByteArray("\xff\x03", 2), 10, &out));
  EXPECT_TRUE(out.isComplete());
}

namespace {

// 一个 5 片的固件（4 整片 + 1 个不满的尾片）和下载目录。
class ResumeStoreTest : public ::testing::Test {
 protected:
  QByteArray chunk(int index) const { return image.mid(index * kChunkSize, kChunkSize); }
  void write(ResumeStore* store, int index) {
    ASSERT_TRUE(chunkMatches(manifest, index, chunk(index)));
    ASSERT_TRUE(store->writeChunk(index, chunk(index), &error)) << error.toStdString();
  }
  int recheckAll(ResumeStore* store) {
    int next = 0;
    while (next < manifest.chunkCount) next = store->recheck(next, 2);
    return store->bitmap().doneCount();
  }
  QString downloadDir() const { return dir.filePath(QStringLiteral("download")); }

  QTemporaryDir dir;
  QByteArray image = randomBytes(4 * kChunkSize + 1000);
  Manifest manifest = manifestFor(image);
  QByteArray raw = serializeManifest(manifest);
  QString error;
};

}  // namespace

TEST_F(ResumeStoreTest, FreshDownloadCreatesFilesOfFullSize) {
  ResumeStore store(downloadDir());
  ASSERT_TRUE(store.open(manifest, raw, &error)) << error.toStdString();
  EXPECT_EQ(store.bitmap().size(), 5);
  EXPECT_EQ(store.bitmap().doneCount(), 0);
  EXPECT_EQ(QFileInfo(store.partPath()).size(), image.size());  // 一开始就预留了整个镜像的空间
  EXPECT_TRUE(QFile::exists(store.statePath()));
  EXPECT_TRUE(store.partPath().endsWith(manifest.pkgId + QStringLiteral(".part")));
}

// 进度不只在内存里：写了几片之后直接销毁对象（相当于进程退出），重新打开能看到进度
TEST_F(ResumeStoreTest, ProgressSurvivesReopen) {
  {
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    write(&store, 0);
    write(&store, 3);
    write(&store, 4);  // 尾片
  }
  ResumeStore store(downloadDir());
  ASSERT_TRUE(store.open(manifest, raw, &error));
  EXPECT_EQ(store.bitmap().doneCount(), 3);
  EXPECT_EQ(store.bitmap().firstMissing(), 1);
  EXPECT_EQ(recheckAll(&store), 3);  // 盘上的内容和 manifest 一致

  write(&store, 1);
  write(&store, 2);
  ASSERT_TRUE(store.flush(&error));
  EXPECT_TRUE(store.bitmap().isComplete());
  QFile part(store.partPath());
  ASSERT_TRUE(part.open(QIODevice::ReadOnly));
  EXPECT_EQ(part.readAll(), image);  // 乱序写入，拼出来和原镜像一字节不差
}

// 每攒够 N 片自动落盘：不调 flush，断点记录里也已经有前 N 片
TEST_F(ResumeStoreTest, SavesEveryNChunksWithoutExplicitFlush) {
  ResumeStore store(downloadDir(), 2);
  ASSERT_TRUE(store.open(manifest, raw, &error));
  write(&store, 0);
  write(&store, 1);  // 满 2 片，自动落盘
  write(&store, 2);  // 这一片还没落盘

  QFile state(store.statePath());
  ASSERT_TRUE(state.open(QIODevice::ReadOnly));
  const QJsonObject obj = QJsonDocument::fromJson(state.readAll()).object();
  EXPECT_EQ(obj.value(QStringLiteral("pkg_id")).toString(), manifest.pkgId);
  EXPECT_EQ(obj.value(QStringLiteral("chunk_count")).toInt(), 5);
  const QByteArray bits = QByteArray::fromBase64(obj.value(QStringLiteral("bitmap")).toString().toLatin1());
  EXPECT_EQ(static_cast<quint8>(bits.at(0)), 0x03);
}

// FT-07 ①：断点记录说已完成，但 .part 里那一片被改了 → 重新校验时只把这一片改回未完成
TEST_F(ResumeStoreTest, RecheckFindsTamperedCache) {
  QString partPath;
  {
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    for (int i = 0; i < 4; ++i) write(&store, i);
    partPath = store.partPath();
  }
  QFile part(partPath);
  ASSERT_TRUE(part.open(QIODevice::ReadWrite));
  ASSERT_TRUE(part.seek(2 * kChunkSize + 77));
  part.write("X", 1);  // 改第 2 片里的一个字节
  part.close();

  ResumeStore store(downloadDir());
  ASSERT_TRUE(store.open(manifest, raw, &error));
  EXPECT_EQ(store.bitmap().doneCount(), 4);  // 位图本身看不出问题
  EXPECT_EQ(recheckAll(&store), 3);
  EXPECT_FALSE(store.bitmap().test(2));
  EXPECT_EQ(store.bitmap().firstMissing(), 2);
}

// FT-07 ②：manifest 变了（固件已更换）→ 旧进度作废，旧包的文件被清掉
TEST_F(ResumeStoreTest, DifferentManifestDiscardsOldProgress) {
  QString oldPart;
  {
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    write(&store, 0);
    oldPart = store.partPath();
  }
  // 另一个包
  const QByteArray otherImage = randomBytes(2 * kChunkSize);
  const Manifest other = manifestFor(otherImage);
  ResumeStore store(downloadDir());
  ASSERT_TRUE(store.open(other, serializeManifest(other), &error));
  EXPECT_EQ(store.bitmap().doneCount(), 0);
  EXPECT_FALSE(QFile::exists(oldPart));

  // 包 ID 相同但 manifest 内容不同：同样不沿用
  store.close();
  Manifest sameIdNewContent = manifestFor(randomBytes(2 * kChunkSize));
  sameIdNewContent.pkgId = other.pkgId;
  ASSERT_TRUE(store.open(other, serializeManifest(other), &error));
  ASSERT_TRUE(store.writeChunk(0, otherImage.left(kChunkSize), &error));
  store.close();
  ASSERT_TRUE(store.open(sameIdNewContent, serializeManifest(sameIdNewContent), &error));
  EXPECT_EQ(store.bitmap().doneCount(), 0);
}

// 断点记录损坏（不是 JSON、位图长度不对）或 .part 丢失：从头开始，不报错也不崩
TEST_F(ResumeStoreTest, CorruptStateStartsOver) {
  QString statePath;
  QString partPath;
  {
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    write(&store, 0);
    statePath = store.statePath();
    partPath = store.partPath();
  }
  const auto overwrite = [&](const QByteArray& content) {
    QFile f(statePath);
    ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write(content);
  };
  {
    overwrite("garbage{{{");
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    EXPECT_EQ(store.bitmap().doneCount(), 0);
    write(&store, 0);
  }
  {
    QFile::remove(partPath);  // 位图还在，数据文件没了
    ResumeStore store(downloadDir());
    ASSERT_TRUE(store.open(manifest, raw, &error));
    EXPECT_EQ(store.bitmap().doneCount(), 0);
    EXPECT_EQ(QFileInfo(partPath).size(), image.size());
  }
}

TEST_F(ResumeStoreTest, DiscardRemovesFiles) {
  ResumeStore store(downloadDir());
  ASSERT_TRUE(store.open(manifest, raw, &error));
  write(&store, 0);
  const QString partPath = store.partPath();
  const QString statePath = store.statePath();
  store.discard();
  EXPECT_FALSE(QFile::exists(partPath));
  EXPECT_FALSE(QFile::exists(statePath));
  EXPECT_FALSE(store.isOpen());
  EXPECT_EQ(store.bitmap().doneCount(), 0);
}

// 下载目录建不出来（路径上有个同名文件）：open 返回失败，不崩
TEST_F(ResumeStoreTest, OpenFailsWhenDirectoryCannotBeCreated) {
  QFile blocker(dir.filePath(QStringLiteral("blocked")));
  ASSERT_TRUE(blocker.open(QIODevice::WriteOnly));
  blocker.close();
  ResumeStore store(dir.filePath(QStringLiteral("blocked/download")));
  EXPECT_FALSE(store.open(manifest, raw, &error));
  EXPECT_FALSE(error.isEmpty());
}
