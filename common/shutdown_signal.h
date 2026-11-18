// 收到停止信号时正常退出（设计 8.3、8.4 节）。
// systemd、launchd 和升级脚本停止程序时发 SIGTERM（Ctrl-C 是 SIGINT）。默认处理是直接结束进程，
// 析构函数都不执行：服务端最后一次审计检查点来不及写，客户端也来不及向服务端说 BYE。
// 这里改成“收到信号 → 事件循环正常退出 → 各对象按顺序析构”。
// Windows 上结束进程（任务计划程序停止任务、Stop-Process）不经过信号，这个函数不起作用。
#pragma once

class QCoreApplication;

namespace fwds {

// 在 app.exec() 之前调用一次。
void quitOnTerminationSignal(QCoreApplication* app);

}  // namespace fwds
