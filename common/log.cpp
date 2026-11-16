#include "common/log.h"

#include <QDateTime>
#include <cstdio>

namespace fwds {

Q_LOGGING_CATEGORY(lcNet, "fwds.net")
Q_LOGGING_CATEGORY(lcSecurity, "fwds.security")
Q_LOGGING_CATEGORY(lcApp, "fwds.app")

namespace {

QtMsgType g_minLevel = QtInfoMsg;

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
  const QByteArray text = msg.toUtf8();
  std::fprintf(stderr, "%s [%s] [%s] %s\n", time.constData(), levelName(type, ctx.category),
               ctx.category ? ctx.category : "default", text.constData());
  std::fflush(stderr);
}

}  // namespace

void initLogging(const QString& level) {
  if (level == QLatin1String("DEBUG")) g_minLevel = QtDebugMsg;
  else if (level == QLatin1String("WARN")) g_minLevel = QtWarningMsg;
  else if (level == QLatin1String("ERROR")) g_minLevel = QtCriticalMsg;
  else g_minLevel = QtInfoMsg;
  qInstallMessageHandler(handler);
}

}  // namespace fwds
