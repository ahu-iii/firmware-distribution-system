#include "common/shutdown_signal.h"

#include <QCoreApplication>
#include <QTimer>
#include <atomic>
#include <csignal>

namespace fwds {

namespace {

// 信号处理函数里只能做极少的事（不能调 Qt），所以只置一个标志，由事件循环里的定时器去看
std::atomic<bool> g_stopRequested{false};

extern "C" void onTerminationSignal(int) { g_stopRequested.store(true); }

}  // namespace

void quitOnTerminationSignal(QCoreApplication* app) {
  std::signal(SIGTERM, onTerminationSignal);
  std::signal(SIGINT, onTerminationSignal);
  auto* timer = new QTimer(app);
  QObject::connect(timer, &QTimer::timeout, app, [app]() {
    if (g_stopRequested.load()) app->quit();
  });
  timer->start(200);
}

}  // namespace fwds
