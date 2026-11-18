// 运行日志：统一格式 "UTC 毫秒时间 [级别] [模块] 内容"，输出到标准错误。
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
