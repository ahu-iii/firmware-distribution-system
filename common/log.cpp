#include "common/log.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <cstdio>

namespace fwds {

Q_LOGGING_CATEGORY(lcNet, "fwds.net")
Q_LOGGING_CATEGORY(lcSecurity, "fwds.security")
Q_LOGGING_CATEGORY(lcApp, "fwds.app")
Q_LOGGING_CATEGORY(lcAudit, "fwds.audit")

LogBus* logBus() {
  static LogBus bus;
  return &bus;
}

namespace {

QtMsgType g_minLevel = QtInfoMsg;

// 日志文件。日志可能从工作线程写（哈希计算、写盘都不在界面线程），所以写文件和轮转都加锁
struct LogFile {
  QMutex mutex;
  QFile file;
  LogFileParams params;
  QString name;
};
LogFile& logFile() {
  static LogFile f;
  return f;
}

QString rotatedPath(const LogFileParams& params, const QString& name, int index) {
  const QString base = QDir(params.dir).filePath(name + QStringLiteral(".log"));
  return index == 0 ? base : base + QStringLiteral(".") + QString::number(index);
}

// 轮转：删掉最旧的，其余依次改名往后挪一位，当前文件变成 .1，再新建一个空的当前文件。
// 调用时已持有锁。
void rotate(LogFile& f) {
  f.file.close();
  QFile::remove(rotatedPath(f.params, f.name, f.params.maxFiles));
  for (int i = f.params.maxFiles - 1; i >= 0; --i) {
    QFile::rename(rotatedPath(f.params, f.name, i), rotatedPath(f.params, f.name, i + 1));
  }
  f.file.open(QIODevice::WriteOnly | QIODevice::Append);
}

void writeToFile(const QByteArray& line) {
  LogFile& f = logFile();
  QMutexLocker lock(&f.mutex);
  if (!f.file.isOpen()) return;
  if (f.file.size() + line.size() > static_cast<qint64>(f.params.maxFileKb) * 1024) rotate(f);
  f.file.write(line);
  f.file.flush();  // 进程被强制结束（模拟断电）前写的日志也要留在文件里
}

// Qt 的枚举值不是按严重程度排的，这里换算成可比较的等级。
int rank(QtMsgType type) {
  switch (type) {
    case QtDebugMsg: return 0;
    case QtInfoMsg: return 1;
    case QtWarningMsg: return 2;
    case QtCriticalMsg: return 3;
    case QtFatalMsg: return 4;
  }
  return 1;
}

const char* levelName(QtMsgType type, const char* category) {
  // 安全分类的告警单独标成 SECURITY，方便检索
  if (category && qstrcmp(category, "fwds.security") == 0 && type != QtDebugMsg) {
    return "SECURITY";
  }
  switch (type) {
    case QtDebugMsg: return "DEBUG";
    case QtInfoMsg: return "INFO";
    case QtWarningMsg: return "WARN";
    case QtCriticalMsg: return "ERROR";
    case QtFatalMsg: return "FATAL";
  }
  return "INFO";
}

void handler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
  if (rank(type) < rank(g_minLevel)) return;
  const QByteArray time =
      QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyy-MM-ddTHH:mm:ss.zzzZ")).toUtf8();
  // 一条日志只占一行：内容里的换行换成空格。日志页按行解析，
  // 设备送来的文字里夹带换行也伪造不出一条“另起一行”的假日志
  QString text = msg;
  text.replace(QLatin1Char('\n'), QLatin1Char(' ')).replace(QLatin1Char('\r'), QLatin1Char(' '));
  const QByteArray line = time + " [" + levelName(type, ctx.category) + "] [" +
                         (ctx.category ? ctx.category : "default") + "] " + text.toUtf8() + "\n";
  std::fputs(line.constData(), stderr);
  std::fflush(stderr);
  writeToFile(line);

  // 安全事件（WARN 及以上）和管理操作记录转给界面
  if (!ctx.category) return;
  const bool security = qstrcmp(ctx.category, "fwds.security") == 0 && rank(type) >= 2;
  const bool audit = qstrcmp(ctx.category, "fwds.audit") == 0;
  if (security || audit) {
    emit logBus()->logEvent(QString::fromUtf8(time), security || rank(type) >= 2, msg);
  }
}

}  // namespace

bool openLogFile(const LogFileParams& params, const QString& name, QString* error) {
  if (!QDir().mkpath(params.dir)) {
    *error = QStringLiteral("无法创建日志目录 %1").arg(params.dir);
    return false;
  }
  LogFile& f = logFile();
  QMutexLocker lock(&f.mutex);
  f.file.close();
  f.params = params;
  f.name = name;
  f.file.setFileName(rotatedPath(params, name, 0));
  if (!f.file.open(QIODevice::WriteOnly | QIODevice::Append)) {
    *error = QStringLiteral("无法打开日志文件 %1").arg(f.file.fileName());
    return false;
  }
  return true;
}

void closeLogFile() {
  LogFile& f = logFile();
  QMutexLocker lock(&f.mutex);
  f.file.close();
}

QStringList logFilePaths(const LogFileParams& params, const QString& name) {
  QStringList paths;
  for (int i = 0; i <= params.maxFiles; ++i) {
    const QString path = rotatedPath(params, name, i);
    if (QFile::exists(path)) paths.append(path);
  }
  return paths;
}

void initLogging(const QString& level) {
  if (level == QLatin1String("DEBUG")) g_minLevel = QtDebugMsg;
  else if (level == QLatin1String("WARN")) g_minLevel = QtWarningMsg;
  else if (level == QLatin1String("ERROR")) g_minLevel = QtCriticalMsg;
  else g_minLevel = QtInfoMsg;
  qInstallMessageHandler(handler);
}

}  // namespace fwds
