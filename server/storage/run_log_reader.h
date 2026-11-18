// RunLogReader：检索运行日志文件（设计 8.5 节，用例 FT-16）。
// 运行日志每条一行："UTC 毫秒时间 [级别] [模块] 内容"（common/log.cpp 写入，换行已换成空格）。
// 按设备、时间段、级别、模块、关键字筛选，结果从新到旧，最多 limit 条。
// 日志写入时就不含密钥、口令、随机数和完整报文（设计 8.5 节），这里原样显示，不做二次加工。
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>

namespace fwds {

struct RunLogLine {
  QDateTime ts;    // UTC
  QString level;   // DEBUG / INFO / WARN / ERROR / SECURITY / FATAL
  QString module;  // fwds.net / fwds.security / fwds.app / fwds.audit / default
  QString text;
};

struct RunLogFilter {
  QString deviceId;  // 非空时只要内容里出现这个设备 ID 的（整词匹配，DEV-01 不会匹配到 DEV-012）
  QDateTime from;    // 有效时只要这个时间及之后的
  QDateTime to;      // 有效时只要这个时间及之前的
  QString level;     // 非空时只要这个级别的
  QString module;    // 非空时只要这个模块的
  QString keyword;   // 非空时只要内容里包含它的（不区分大小写）
  int limit = 1000;
};

struct RunLogResult {
  QList<RunLogLine> lines;  // 从新到旧
  bool truncated = false;   // 符合条件的不止 limit 条，只返回了最新的 limit 条
  int scannedLines = 0;     // 一共读了多少行
};

// 把一行文字解析成一条日志；格式不对返回 false。
bool parseRunLogLine(const QString& line, RunLogLine* out);

// files 从新到旧排（logFilePaths 给出的顺序）。读不了的文件跳过。
RunLogResult searchRunLog(const QStringList& files, const RunLogFilter& filter);

}  // namespace fwds
