// 重连退避：按配置的序列依次取等待时间，取到末尾后保持最后一个值（封顶）。
// 默认序列 1、2、4、8、16、30 秒（协议第 8 节）。
#pragma once

#include <QList>

namespace fwds {

class Backoff {
 public:
  explicit Backoff(const QList<int>& delaysMs) : delaysMs_(delaysMs) {}

  // 下一次重连前要等待的毫秒数，并前进一步。
  int next() {
    if (delaysMs_.isEmpty()) return 0;
    const int delay = delaysMs_.at(index_);
    if (index_ < delaysMs_.size() - 1) ++index_;
    return delay;
  }

  // 登录成功后调用，下次断线重新从第一个值开始。
  void reset() { index_ = 0; }

 private:
  QList<int> delaysMs_;
  qsizetype index_ = 0;
};

}  // namespace fwds
