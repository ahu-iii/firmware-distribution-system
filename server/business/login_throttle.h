// LoginThrottle：设备登录失败锁定（设计第 14 节，错误码 2007，用例 ST-30）。
// 同一个键（设备 ID 或对端 IP）在 windowMs 内失败 maxFailures 次，锁定 lockMs。
// 只放在内存里：服务端重启后清零，攻击者要重新累计。
// 时间由调用方传入（毫秒），方便单元测试。
#pragma once

#include <QHash>
#include <QList>
#include <QString>

namespace fwds {

class LoginThrottle {
 public:
  LoginThrottle(int maxFailures, qint64 windowMs, qint64 lockMs)
      : maxFailures_(maxFailures), windowMs_(windowMs), lockMs_(lockMs) {}

  // 该键当前是否处于锁定期。
  bool isLocked(const QString& key, qint64 nowMs) const;

  // 记一次失败。返回 true 表示这次失败触发了锁定。
  bool recordFailure(const QString& key, qint64 nowMs);

 private:
  struct Entry {
    QList<qint64> failures;  // 窗口内各次失败的时间
    qint64 lockedUntil = 0;  // 0 表示没有锁定
  };
  void prune(qint64 nowMs);

  int maxFailures_;
  qint64 windowMs_;
  qint64 lockMs_;
  QHash<QString, Entry> entries_;
  qsizetype pruneAt_ = 1024;  // 记录的键达到这个数时清理一次过期项
};

}  // namespace fwds
