#include "server/storage/run_log_reader.h"

#include <QFile>
#include <QRegularExpression>

namespace fwds {

bool parseRunLogLine(const QString& line, RunLogLine* out) {
  // 2026-11-18T04:51:05.429Z [INFO] [fwds.net] session 1 "DEV-002" login ok
  static const QRegularExpression kLine(
      QStringLiteral("^(\\S+) \\[([A-Z]+)\\] \\[([^\\]]+)\\] (.*)$"));
  const QRegularExpressionMatch m = kLine.match(line);
  if (!m.hasMatch()) return false;
  const QDateTime ts = QDateTime::fromString(m.captured(1), Qt::ISODateWithMs);
  if (!ts.isValid()) return false;
  out->ts = ts.toUTC();
  out->level = m.captured(2);
  out->module = m.captured(3);
  out->text = m.captured(4);
  return true;
}

namespace {

bool matches(const RunLogLine& line, const RunLogFilter& filter, const QRegularExpression& device) {
  if (filter.from.isValid() && line.ts < filter.from) return false;
  if (filter.to.isValid() && line.ts > filter.to) return false;
  if (!filter.level.isEmpty() && line.level != filter.level) return false;
  if (!filter.module.isEmpty() && line.module != filter.module) return false;
  if (!filter.keyword.isEmpty() && !line.text.contains(filter.keyword, Qt::CaseInsensitive)) {
    return false;
  }
  if (!filter.deviceId.isEmpty() && !device.match(line.text).hasMatch()) return false;
  return true;
}

}  // namespace

RunLogResult searchRunLog(const QStringList& files, const RunLogFilter& filter) {
  RunLogResult result;
  // 设备 ID 整词匹配：前后不能紧挨着字母、数字、下划线或连字符
  const QRegularExpression device(QStringLiteral("(?<![A-Za-z0-9_-])%1(?![A-Za-z0-9_-])")
                                      .arg(QRegularExpression::escape(filter.deviceId)));
  // 文件从新到旧；每个文件里的行从旧到新，所以每个文件倒着取
  for (const QString& path : files) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) continue;
    const QList<QByteArray> rows = file.readAll().split('\n');
    for (auto it = rows.crbegin(); it != rows.crend(); ++it) {
      if (it->isEmpty()) continue;
      ++result.scannedLines;
      RunLogLine line;
      if (!parseRunLogLine(QString::fromUtf8(*it), &line)) continue;
      if (!matches(line, filter, device)) continue;
      if (result.lines.size() >= filter.limit) {
        result.truncated = true;
        return result;
      }
      result.lines.append(line);
    }
  }
  return result;
}

}  // namespace fwds
