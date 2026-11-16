// DispatchGate：全局“允许下发”开关（设计 4.2 节“默认只监控”，检查项 7-1）。
// 推送固件是对现场设备的写操作，和监控分开控制：
//   - 每次启动默认关闭，开关状态不落盘，服务端重启后回到“只监控”；
//   - 只有维护员能打开（setEnabled 是私有的，只有 AdminService 检查角色后才能调）；
//   - 发布模块（RolloutManager）在每次推送前查询 enabled()，关闭时拒绝推送。
#pragma once

#include <QObject>

namespace fwds {

class DispatchGate : public QObject {
  Q_OBJECT
 public:
  explicit DispatchGate(QObject* parent = nullptr) : QObject(parent) {}

  bool enabled() const { return enabled_; }

 signals:
  void changed(bool enabled);

 private:
  friend class AdminService;

  void setEnabled(bool enabled) {
    if (enabled_ == enabled) return;
    enabled_ = enabled;
    emit changed(enabled_);
  }

  bool enabled_ = false;  // 默认关闭
};

}  // namespace fwds
