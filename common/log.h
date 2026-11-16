// 运行日志：统一格式 "UTC 毫秒时间 [级别] [模块] 内容"，输出到标准错误。
// 级别对应设计 8.5 节：DEBUG / INFO / WARN / ERROR，SECURITY 用 fwds.security 分类。
// 日志里不得出现密钥、口令和完整报文。
#pragma once

#include <QLoggingCategory>
#include <QString>

namespace fwds {

Q_DECLARE_LOGGING_CATEGORY(lcNet)       // 网络层
Q_DECLARE_LOGGING_CATEGORY(lcSecurity)  // 安全事件（非法帧、疑似重放等）
Q_DECLARE_LOGGING_CATEGORY(lcApp)       // 程序启动与配置

// 安装日志格式并按级别过滤。level 取 DEBUG / INFO / WARN / ERROR。
void initLogging(const QString& level);

}  // namespace fwds
