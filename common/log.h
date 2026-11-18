// 运行日志：统一格式 "UTC 毫秒时间 [级别] [模块] 内容"，输出到标准错误；
// 打开日志文件之后同时写进文件，按大小轮转（设计 8.5 节）。服务端“运行日志”页读的就是这些文件。
// 级别对应设计 8.5 节：DEBUG / INFO / WARN / ERROR，SECURITY 用 fwds.security 分类。
// 日志里不得出现密钥、口令和完整报文。
#pragma once

#include <QLoggingCategory>
#include <QObject>
#include <QString>

namespace fwds {

Q_DECLARE_LOGGING_CATEGORY(lcNet)       // 网络层
Q_DECLARE_LOGGING_CATEGORY(lcSecurity)  // 安全事件（非法帧、疑似重放等）
Q_DECLARE_LOGGING_CATEGORY(lcApp)       // 程序启动与配置
Q_DECLARE_LOGGING_CATEGORY(lcAudit)     // 管理操作留痕：谁、做了什么、结果（同时写入审计日志表的哈希链）

// 安装日志格式并按级别过滤。level 取 DEBUG / INFO / WARN / ERROR。
void initLogging(const QString& level);

// 运行日志文件的位置和轮转规则（配置 [log] max_file_kb、max_files；目录见各端配置）。
struct LogFileParams {
  QString dir;            // 日志目录，不存在时自动创建
  int maxFileKb = 1024;   // 一个文件写到多大就轮转
  int maxFiles = 5;       // 保留几个旧文件：name.log.1（最近的）… name.log.N（最早的）
};

// 打开 dir/name.log 追加写入。之后每条日志写完标准错误再写文件；
// 文件写到 maxFileKb 就轮转：name.log → name.log.1，原来的 .1 → .2 ……，超出 maxFiles 的删掉。
bool openLogFile(const LogFileParams& params, const QString& name, QString* error);

// 关闭日志文件，之后只写标准错误（单元测试用）。
void closeLogFile();

// 当前的日志文件，从新到旧：name.log、name.log.1、name.log.2 ……（只列存在的）。
QStringList logFilePaths(const LogFileParams& params, const QString& name);

// LogBus：把安全事件和管理操作的日志同时转给界面（服务端“安全告警”列表）。
// 界面只连这个信号，不直接读日志文件；内容与写到标准错误的那一行相同，同样不含敏感数据。
class LogBus : public QObject {
  Q_OBJECT
 signals:
  // alert 为 true 表示这是一条安全告警（界面标红），false 是普通的管理操作记录。
  // 信号不叫 event：QObject 已有虚函数 event(QEvent*)，同名会把它遮住（clang 报 -Woverloaded-virtual）
  void logEvent(const QString& time, bool alert, const QString& text);
};
LogBus* logBus();

}  // namespace fwds
