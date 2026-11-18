// EventReporter：决定升级过程中哪些事情要作为事件上报（协议 5.7 节），交给 EventOutbox 落盘和发送。
//   PROGRESS  进入 NOTIFIED、DOWNLOADING、VERIFYING、WRITING、REBOOTING 时各报一次；
//             DOWNLOADING 和 WRITING 阶段进度每涨 5% 再报一次
//   ALERT     Updater 的安全告警（3001、3003、3004、3005）
//   RESULT    一次升级的最终结果（SUCCESS / FAILED / ROLLED_BACK），带上结束时运行的固件
// 最终状态（SUCCESS、FAILED、ROLLED_BACK）只用 RESULT 报，不再另发 PROGRESS。
#pragma once

#include <QObject>

#include "client/business/event_outbox.h"
#include "client/business/updater.h"

namespace fwds {

class EventReporter : public QObject {
  Q_OBJECT
 public:
  // updater、outbox 由调用方持有，必须比 EventReporter 活得久。
  EventReporter(Updater* updater, EventOutbox* outbox, QObject* parent = nullptr);

 private:
  void onState(Updater::State state);
  void onProgress(int percent);
  void onAlert(int code, const QString& detail);
  void onFinished(const QString& result, int code, const QString& detail);
  void recordProgress();

  Updater* updater_;
  EventOutbox* outbox_;
  int lastReported_ = -1;  // 本阶段最近一次上报的进度
};

}  // namespace fwds
