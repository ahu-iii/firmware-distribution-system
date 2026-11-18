// 运行日志文件与“运行日志”页的检索（设计 8.5 节，用例 FT-16）。
//   写入：每条一行，内容里的换行换成空格；写满就轮转，只保留规定个数的旧文件
//   检索：按设备（整词）、级别、模块、关键字、时间段筛选，从新到旧，跨轮转文件，超过上限只给最新的
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/log.h"
#include "server/storage/run_log_reader.h"

using namespace fwds;

namespace {

void writeFile(const QString& path, const QStringList& lines) {
  QFile file(path);
  ASSERT_TRUE(file.open(QIODevice::WriteOnly));
  file.write((lines.join(QLatin1Char('\n')) + QLatin1Char('\n')).toUtf8());
}

// 一组固定的日志：两个文件，fwds-server.log 是新的，.1 是轮转出去的旧文件
class RunLogSearch : public ::testing::Test {
 protected:
  RunLogSearch() {
    params.dir = dir.path();
    writeFile(dir.filePath(QStringLiteral("fwds-server.log.1")),
              {QStringLiteral("2026-11-18T08:00:00.000Z [INFO] [fwds.net] session 1 \"DEV-001\" login ok"),
               QStringLiteral("2026-11-18T08:00:01.000Z [INFO] [fwds.net] session 2 \"DEV-012\" login ok")});
    writeFile(dir.filePath(QStringLiteral("fwds-server.log")),
              {QStringLiteral("2026-11-18T09:00:00.000Z [INFO] [fwds.app] UPDATE_NOTIFY sent to DEV-001 package 6f1c"),
               QStringLiteral("不是日志格式的一行"),
               QStringLiteral("2026-11-18T09:00:05.000Z [WARN] [fwds.app] 发布 #3：设备 DEV-001 上报结果 ROLLED_BACK 3007 selftest"),
               QStringLiteral("2026-11-18T09:00:06.000Z [SECURITY] [fwds.security] session 9 127.0.0.1 TLS handshake failed")});
  }
  RunLogResult search(const RunLogFilter& filter) {
    return searchRunLog(logFilePaths(params, QStringLiteral("fwds-server")), filter);
  }

  QTemporaryDir dir;
  LogFileParams params;
};

}  // namespace

TEST(RunLogLine, Parses) {
  RunLogLine line;
  ASSERT_TRUE(parseRunLogLine(
      QStringLiteral("2026-11-18T04:51:05.429Z [INFO] [fwds.net] session 1 \"DEV-002\" login ok"), &line));
  EXPECT_EQ(line.ts, QDateTime(QDate(2026, 11, 18), QTime(4, 51, 5, 429), Qt::UTC));
  EXPECT_EQ(line.level, QStringLiteral("INFO"));
  EXPECT_EQ(line.module, QStringLiteral("fwds.net"));
  EXPECT_EQ(line.text, QStringLiteral("session 1 \"DEV-002\" login ok"));
  EXPECT_FALSE(parseRunLogLine(QStringLiteral("garbage"), &line));
  EXPECT_FALSE(parseRunLogLine(QStringLiteral("notatime [INFO] [fwds.net] x"), &line));
}

TEST_F(RunLogSearch, NewestFirstAcrossRotatedFiles) {
  const RunLogResult r = search(RunLogFilter());
  ASSERT_EQ(r.lines.size(), 5);  // 格式不对的那一行跳过
  EXPECT_EQ(r.lines.first().level, QStringLiteral("SECURITY"));
  EXPECT_TRUE(r.lines.last().text.contains(QStringLiteral("session 1")));
  EXPECT_EQ(r.scannedLines, 6);
  EXPECT_FALSE(r.truncated);
}

TEST_F(RunLogSearch, DeviceMatchesWholeIdOnly) {
  RunLogFilter f;
  f.deviceId = QStringLiteral("DEV-001");
  EXPECT_EQ(search(f).lines.size(), 3);  // DEV-012 那一行不算
  f.deviceId = QStringLiteral("DEV-01");
  EXPECT_EQ(search(f).lines.size(), 0);
}

TEST_F(RunLogSearch, LevelModuleKeywordAndTime) {
  RunLogFilter f;
  f.level = QStringLiteral("WARN");
  ASSERT_EQ(search(f).lines.size(), 1);
  EXPECT_TRUE(search(f).lines.first().text.contains(QStringLiteral("3007")));

  f = RunLogFilter();
  f.module = QStringLiteral("fwds.net");
  EXPECT_EQ(search(f).lines.size(), 2);

  f = RunLogFilter();
  f.keyword = QStringLiteral("rolled_back");  // 不区分大小写
  EXPECT_EQ(search(f).lines.size(), 1);
  f.keyword = QStringLiteral("回滚");
  EXPECT_EQ(search(f).lines.size(), 0);

  f = RunLogFilter();
  f.from = QDateTime(QDate(2026, 11, 18), QTime(9, 0, 1), Qt::UTC);
  f.to = QDateTime(QDate(2026, 11, 18), QTime(9, 0, 5), Qt::UTC);
  ASSERT_EQ(search(f).lines.size(), 1);  // 两端都含
  EXPECT_EQ(search(f).lines.first().level, QStringLiteral("WARN"));
}

TEST_F(RunLogSearch, LimitKeepsNewest) {
  RunLogFilter f;
  f.limit = 2;
  const RunLogResult r = search(f);
  ASSERT_EQ(r.lines.size(), 2);
  EXPECT_TRUE(r.truncated);
  EXPECT_EQ(r.lines.first().level, QStringLiteral("SECURITY"));
}

// 日志写进文件：一条一行，换行被换掉；写满就轮转，旧文件最多保留 max_files 个
TEST(RunLogFile, WritesOneLinePerEntryAndRotates) {
  QTemporaryDir dir;
  LogFileParams params;
  params.dir = dir.filePath(QStringLiteral("logs"));  // 不存在，自动创建
  params.maxFileKb = 16;
  params.maxFiles = 2;
  QString error;
  initLogging(QStringLiteral("INFO"));
  ASSERT_TRUE(openLogFile(params, QStringLiteral("unit"), &error)) << error.toStdString();
  for (int i = 0; i < 400; ++i) qCInfo(lcApp).noquote() << "filler line" << i << QString(60, QLatin1Char('x'));
  qCWarning(lcApp).noquote() << "the last one";
  closeLogFile();
  qInstallMessageHandler(nullptr);

  const QStringList files = logFilePaths(params, QStringLiteral("unit"));
  ASSERT_EQ(files.size(), 3);  // unit.log、unit.log.1、unit.log.2；更早的已经删掉
  EXPECT_FALSE(QFile::exists(QDir(params.dir).filePath(QStringLiteral("unit.log.3"))));
  for (const QString& path : files) EXPECT_LE(QFileInfo(path).size(), 16 * 1024);

  const RunLogResult r = searchRunLog(files, RunLogFilter());
  ASSERT_FALSE(r.lines.isEmpty());
  EXPECT_EQ(r.lines.first().text, QStringLiteral("the last one"));
  EXPECT_EQ(r.lines.first().level, QStringLiteral("WARN"));
  EXPECT_EQ(r.lines.size(), r.scannedLines);  // 每一行都是完整的一条

  // 内容里的换行换成空格：设备送来的文字夹带换行，也伪造不出另起一行的假日志
  ASSERT_TRUE(openLogFile(params, QStringLiteral("nl"), &error));
  initLogging(QStringLiteral("INFO"));
  qCInfo(lcApp).noquote() << "a\nb\r\nc";
  closeLogFile();
  qInstallMessageHandler(nullptr);
  const RunLogResult nl = searchRunLog(logFilePaths(params, QStringLiteral("nl")), RunLogFilter());
  ASSERT_EQ(nl.lines.size(), 1);
  EXPECT_EQ(nl.lines.first().text, QStringLiteral("a b  c"));
}
