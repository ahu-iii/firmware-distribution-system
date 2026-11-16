#include "server/business/login_throttle.h"

namespace fwds {

bool LoginThrottle::isLocked(const QString& key, qint64 nowMs) const {
  const auto it = entries_.constFind(key);
  return it != entries_.constEnd() && nowMs < it->lockedUntil;
}

bool LoginThrottle::recordFailure(const QString& key, qint64 nowMs) {
  // 防止有人用大量不同来源把内存撑大：键多了就清一次过期项。
  // 清完把下次清理的门槛定为剩余数量的两倍，这样平均下来每次调用的开销是常数。
  if (entries_.size() >= pruneAt_) {
    prune(nowMs);
    pruneAt_ = qMax<qsizetype>(1024, entries_.size() * 2);
  }

  Entry& entry = entries_[key];
  if (nowMs < entry.lockedUntil) return false;  // 已经在锁定期，不重复触发

  // 只保留窗口内的失败记录，再加上这一次
  while (!entry.failures.isEmpty() && nowMs - entry.failures.first() >= windowMs_) {
    entry.failures.removeFirst();
  }
  entry.failures.append(nowMs);
  if (entry.failures.size() < maxFailures_) return false;

  entry.lockedUntil = nowMs + lockMs_;
  entry.failures.clear();
  return true;
}

void LoginThrottle::prune(qint64 nowMs) {
  for (auto it = entries_.begin(); it != entries_.end();) {
    const bool lockOver = nowMs >= it->lockedUntil;
    const bool windowOver = it->failures.isEmpty() || nowMs - it->failures.last() >= windowMs_;
    if (lockOver && windowOver) it = entries_.erase(it);
    else ++it;
  }
}

}  // namespace fwds
