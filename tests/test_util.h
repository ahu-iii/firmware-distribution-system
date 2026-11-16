#pragma once

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <functional>

// 转动事件循环直到 done() 为真或超时。返回是否在超时前满足条件。
inline bool waitFor(const std::function<bool()>& done, int timeoutMs = 3000) {
  QElapsedTimer timer;
  timer.start();
  while (!done()) {
    if (timer.elapsed() > timeoutMs) return false;
    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
  }
  return true;
}

// 单纯转动事件循环一段时间。
inline void spin(int ms) {
  QElapsedTimer timer;
  timer.start();
  while (timer.elapsed() < ms) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
  }
}
