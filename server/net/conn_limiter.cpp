#include "server/net/conn_limiter.h"

namespace fwds {

bool ConnLimiter::tryAcquire(const QHostAddress& peer) {
  if (total_ >= maxTotal_) return false;
  const int current = perIp_.value(peer, 0);
  if (current >= maxPerIp_) return false;
  perIp_.insert(peer, current + 1);
  ++total_;
  return true;
}

void ConnLimiter::release(const QHostAddress& peer) {
  const auto it = perIp_.find(peer);
  if (it == perIp_.end()) return;
  if (--it.value() <= 0) perIp_.erase(it);
  --total_;
}

}  // namespace fwds
