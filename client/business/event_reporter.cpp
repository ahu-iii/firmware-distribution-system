#include "client/business/event_reporter.h"

namespace fwds {

namespace {

constexpr int kProgressStep = 5;  // 进度每涨 5% 报一次
constexpr int kMaxDetail = 200;   // 说明文字最多带多少个字符

}  // namespace

EventReporter::EventReporter(Updater* updater, EventOutbox* outbox, QObject* parent)
    : QObject(parent), updater_(updater), outbox_(outbox) {
  connect(updater, &Updater::stateChanged, this, &EventReporter::onState);
  connect(updater, &Updater::progressChanged, this, &EventReporter::onProgress);
  connect(updater, &Updater::alertRaised, this, &EventReporter::onAlert);
  connect(updater, &Updater::finished, this, &EventReporter::onFinished);
}

void EventReporter::onState(Updater::State state) {
  switch (state) {
    case Updater::State::Notified:
    case Updater::State::Downloading:
    case Updater::State::Verifying:
    case Updater::State::Writing:
    case Updater::State::Rebooting:
      recordProgress();  // 状态变化立即上报
      break;
    default:
      break;  // IDLE 不报；最终状态由 RESULT 报
  }
}

void EventReporter::onProgress(int percent) {
  const Updater::State state = updater_->state();
  if (state != Updater::State::Downloading && state != Updater::State::Writing) return;
  if (percent >= lastReported_ + kProgressStep || (percent == 100 && lastReported_ < 100)) {
    recordProgress();
  }
}

void EventReporter::recordProgress() {
  lastReported_ = updater_->progress();
  QJsonObject fields;
  fields.insert(QStringLiteral("pkg_id"), updater_->pkgId());
  fields.insert(QStringLiteral("state"), updater_->stateName());
  fields.insert(QStringLiteral("progress"), lastReported_);
  outbox_->record(MsgType::Progress, fields);
}

void EventReporter::onAlert(int code, const QString& detail) {
  QJsonObject fields;
  fields.insert(QStringLiteral("pkg_id"), updater_->pkgId());
  fields.insert(QStringLiteral("code"), code);
  fields.insert(QStringLiteral("detail"), detail.left(kMaxDetail));
  outbox_->record(MsgType::Alert, fields);
}

void EventReporter::onFinished(const QString& result, int code, const QString& detail) {
  // 结果里带上升级结束后设备实际运行的固件：成功时是新版本，失败或回滚时是原来的版本
  const BootResult& boot = updater_->bootState();
  QJsonObject fields;
  fields.insert(QStringLiteral("pkg_id"), updater_->pkgId());
  fields.insert(QStringLiteral("release_id"), updater_->releaseId());
  fields.insert(QStringLiteral("result"), result);
  fields.insert(QStringLiteral("code"), code);
  fields.insert(QStringLiteral("detail"), detail.left(kMaxDetail));
  fields.insert(QStringLiteral("fw_version"), boot.hasFirmware ? boot.running.version : QString());
  fields.insert(QStringLiteral("security_version"), boot.hasFirmware ? boot.running.securityVersion : 0);
  fields.insert(QStringLiteral("active_slot"), boot.config.active);
  outbox_->record(MsgType::Result, fields);
}

}  // namespace fwds
