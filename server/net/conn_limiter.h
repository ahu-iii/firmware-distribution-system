// ConnLimiter：连接数限制（设计第 14 节）。总数和单个 IP 的连接数各有上限。
#pragma once

#include <QHash>
#include <QHostAddress>

namespace fwds {

class ConnLimiter {
 public:
  ConnLimiter(int maxTotal, int maxPerIp) : maxTotal_(maxTotal), maxPerIp_(maxPerIp) {}

  // 新连接到来时调用。未超限则计数并返回 true；超限返回 false，不计数。
  bool tryAcquire(const QHostAddress& peer);

  // 连接关闭时调用，与成功的 tryAcquire 一一对应。
  void release(const QHostAddress& peer);

  int total() const { return total_; }

 private:
  int maxTotal_;
  int maxPerIp_;
  int total_ = 0;
  QHash<QHostAddress, int> perIp_;
};

}  // namespace fwds
