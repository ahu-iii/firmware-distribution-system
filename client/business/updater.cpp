#include "client/business/updater.h"

#include <QDir>
#include <QJsonDocument>

#include "common/log.h"
#include "common/update_messages.h"

namespace fwds {

Updater::Updater(const ClientConfig& config, const ManifestVerifier& verifier,
                 Downloader::SendFn send, QObject* parent)
    : QObject(parent),
      config_(config),
      verifier_(verifier),
      send_(send),
      bootloader_(config.dataDir, verifier, config.model),
      slots_(config.dataDir),
      validator_(verifier, config.model, antiRollback_),
      store_(QDir(config.dataDir).filePath(QStringLiteral("download"))),
      downloader_(config.deviceId, validator_, &store_, config.protocol, send) {
  workTimer_.setInterval(0);
  connect(&workTimer_, &QTimer::timeout, this, &Updater::workStep);

  // Downloader 负责 NOTIFIED、DOWNLOADING 两段，它的状态、进度、告警原样转出去
  connect(&downloader_, &Downloader::stateChanged, this, &Updater::onDownloaderState);
  connect(&downloader_, &Downloader::progressChanged, this, [this](int) { reportProgress(); });
  connect(&downloader_, &Downloader::alertRaised, this, &Updater::alertRaised);
  connect(&downloader_, &Downloader::failed, this, [this](int code, const QString& detail) {
    emit finished(QStringLiteral("FAILED"), code, detail);
  });
  connect(&downloader_, &Downloader::downloadCompleted, this, &Updater::onDownloadCompleted);
}

Updater::~Updater() = default;

void Updater::powerOn() {
  boot_ = bootloader_.boot();
  applyBoot();
  // 上次升级如果停在“已写入、未确认”，这次启动就是它的结论，照常报告
  if (boot_.outcome == BootResult::Outcome::Upgraded) {
    setState(State::Success);
    emit finished(QStringLiteral("SUCCESS"), 0, QString());
  } else if (boot_.outcome == BootResult::Outcome::RolledBack) {
    setState(State::RolledBack);
    emit finished(QStringLiteral("ROLLED_BACK"), static_cast<int>(boot_.code), boot_.detail);
  }
}

void Updater::applyBoot() {
  // 防降级的两个基准：最小安全版本号、正在运行的版本（恢复模式下没有，传空串）
  antiRollback_.update(boot_.config.minSecurityVersion,
                       boot_.hasFirmware ? boot_.running.version : QString());
}

void Updater::setOnline(bool online) { downloader_.setOnline(online); }

void Updater::handleFrame(const Frame& frame) {
  const MsgType type = static_cast<MsgType>(frame.type);

  // ---- 校验、写入、重启期间：下载已经结束，帧不再交给 Downloader ----
  if (installing()) {
    if (type == MsgType::UpdateCancel && state_ == State::Verifying) {
      // 写入之前收到取消：放弃升级，删除临时文件。进入 WRITING 之后的取消不处理，
      // 照常写完，由 A/B 分区保证可以回退（协议 5.4 节）
      UpdateCancel cancel;
      if (parseUpdateCancel(frame.body, &cancel) && cancel.deviceId == config_.deviceId &&
          cancel.pkgId == downloader_.manifest().pkgId) {
        failInstall(ErrorCode::Cancelled,
                    QStringLiteral("服务端取消升级：%1").arg(cancel.reason.left(64)), false, true);
      }
    } else if (type == MsgType::UpdateNotify) {
      // 同一个包的重复通知不用理会；别的包回 3013 BUSY
      UpdateNotify notify;
      if (parseUpdateNotify(frame.body, &notify) && notify.deviceId == config_.deviceId &&
          notify.pkgId != downloader_.manifest().pkgId) {
        QJsonObject body;
        body.insert(QStringLiteral("code"), static_cast<int>(ErrorCode::Busy));
        body.insert(QStringLiteral("message"), QString::fromLatin1(errorName(ErrorCode::Busy)));
        send_(MsgType::Error, QJsonDocument(body).toJson(QJsonDocument::Compact));
      }
    }
    return;
  }

  // ---- 空闲或下载中 ----
  if (type == MsgType::UpdateNotify) {
    UpdateNotify notify;
    if (parseUpdateNotify(frame.body, &notify) && notify.deviceId == config_.deviceId) {
      // 设备重新登录后，服务端会把已下发的包再通知一次。两种情况不用再升级：
      if (boot_.hasFirmware && notify.pkgId == boot_.running.pkgId) {
        qCInfo(lcApp) << "UPDATE_NOTIFY for the firmware already running, ignored";
        return;
      }
      if (notify.pkgId == rolledBackPkgId_) {
        qCWarning(lcApp) << "UPDATE_NOTIFY for a package that was just rolled back, ignored";
        return;
      }
    }
    // 其余情况（包括格式不对、不是发给自己的）都交给 Downloader 按规矩处理
  }
  downloader_.handleFrame(frame);
}

void Updater::onDownloaderState(Downloader::State state) {
  switch (state) {
    case Downloader::State::Notified: setState(State::Notified); break;
    case Downloader::State::Downloading: setState(State::Downloading); break;
    case Downloader::State::Failed: setState(State::Failed); break;
    case Downloader::State::Idle:
    case Downloader::State::Downloaded: break;  // 分片收齐后由 onDownloadCompleted 接手
  }
}

// ---------------- VERIFYING ----------------

void Updater::onDownloadCompleted(const QString& partPath) {
  // 分片在下载时逐片校验过，但从那时到现在文件一直躺在磁盘上，可能被改。
  // 写入 Flash 之前把整个镜像从头再算一遍，manifest 签名也再验一遍（设计 12.2 节）
  part_.setFileName(partPath);
  if (!part_.open(QIODevice::ReadOnly)) {
    failInstall(ErrorCode::ImageTampered, QStringLiteral("下载的镜像无法读取"), true, true);
    return;
  }
  check_ = std::make_unique<ImageCheck>(&part_, downloader_.manifest());
  setState(State::Verifying);
  reportProgress();
  workTimer_.start();
}

void Updater::workStep() {
  if (state_ == State::Verifying) verifyStep();
  else if (state_ == State::Writing) writeStep();
  else workTimer_.stop();
}

void Updater::verifyStep() {
  QString detail;
  const ImageCheck::Step step = check_->step(kImageCheckStepChunks, &detail);
  reportProgress();
  if (step == ImageCheck::Step::More) return;  // 没查完，定时器会再触发
  if (step == ImageCheck::Step::Failed) {
    // 镜像和签名保护的哈希对不上：不写入，删除临时文件，告警
    failInstall(ErrorCode::ImageTampered, detail, true, true);
    return;
  }
  // 再验一次签名，并确认验出来的还是刚才用来核对镜像的那一份 manifest
  Manifest again;
  if (verifier_.verify(downloader_.manifestRaw(), downloader_.signature(), &again, &detail) !=
          ManifestCheck::Ok ||
      again.imageSha256 != downloader_.manifest().imageSha256) {
    failInstall(ErrorCode::ImageTampered, QStringLiteral("写入前复验签名未通过"), true, true);
    return;
  }
  check_.reset();
  part_.close();
  startWriting();
}

// ---------------- WRITING ----------------

void Updater::startWriting() {
  // 只写非活动分区。正在运行的分区从头到尾不碰，写入途中断电也还能从它启动
  targetSlot_ = otherSlot(boot_.config.active);
  QString error;
  if (!writer_.begin(slots_.slotDir(targetSlot_), part_.fileName(), 0,
                     downloader_.manifest().imageSize, &error)) {
    failInstall(ErrorCode::WriteFailed, error, false, false);
    return;
  }
  qCInfo(lcApp).noquote() << "writing" << downloader_.manifest().version << "to slot" << targetSlot_;
  setState(State::Writing);
  reportProgress();
}

void Updater::writeStep() {
  QString error;
  // 每次拷 1 MB，然后回到事件循环
  if (!writer_.copySome(static_cast<qint64>(kImageCheckStepChunks) * kChunkSize, &error)) {
    failInstall(ErrorCode::WriteFailed, error, false, false);
    return;
  }
  reportProgress();
  if (writer_.atEnd()) commitWrite();
}

void Updater::commitWrite() {
  workTimer_.stop();
  QString error;
  // ① 镜像刷盘，写入 manifest 和签名
  if (!writer_.finish(downloader_.manifestRaw(), downloader_.signature(), &error)) {
    failInstall(ErrorCode::WriteFailed, error, false, false);
    return;
  }
  // ② 最后一步才登记 pending。在这之前断电，boot.json 里没有 pending，下次仍从旧分区启动
  BootConfig config = boot_.config;
  config.pending = targetSlot_;
  config.bootAttempts = 0;
  if (!saveBootConfig(slots_.bootConfigPath(), config, &error)) {
    failInstall(ErrorCode::WriteFailed, error, false, false);
    return;
  }
  boot_.config = config;
  store_.discard();  // 固件已在分区里，下载用的临时文件可以删了

  // ③ 模拟重启：先让网络层说 BYE 并断开，过一会儿“上电”
  setState(State::Rebooting);
  emit rebootRequested();
  QTimer::singleShot(config_.rebootDelayMs, this, &Updater::reboot);
}

// ---------------- REBOOTING ----------------

void Updater::reboot() {
  const QString pkgId = downloader_.manifest().pkgId;
  boot_ = bootloader_.boot();
  applyBoot();
  if (boot_.outcome == BootResult::Outcome::Upgraded) {
    setState(State::Success);
    emit finished(QStringLiteral("SUCCESS"), 0, QString());
  } else {
    rolledBackPkgId_ = pkgId;
    setState(State::RolledBack);
    emit finished(QStringLiteral("ROLLED_BACK"), static_cast<int>(boot_.code), boot_.detail);
  }
  emit rebootFinished();
}

// ---------------- 公共部分 ----------------

void Updater::failInstall(ErrorCode code, const QString& detail, bool alert, bool discardDownload) {
  workTimer_.stop();
  check_.reset();
  part_.close();
  writer_.abort();
  // 镜像本身有问题或升级被取消：删除临时文件。只是写分区失败：留着，下次不用重新下载
  if (discardDownload) store_.discard();
  else store_.close();
  qCWarning(alert ? lcSecurity() : lcApp()).noquote()
      << "update failed:" << errorName(code) << detail;
  setState(State::Failed);
  if (alert) emit alertRaised(static_cast<int>(code), detail);
  emit finished(QStringLiteral("FAILED"), static_cast<int>(code), detail);
}

void Updater::setState(State state) {
  if (state_ == state) return;
  state_ = state;
  lastPercent_ = -1;
  emit stateChanged(state);
}

void Updater::reportProgress() {
  const int percent = progress();
  if (percent == lastPercent_) return;
  lastPercent_ = percent;
  emit progressChanged(percent);
}

QString Updater::stateName() const {
  switch (state_) {
    case State::Idle: return QStringLiteral("IDLE");
    case State::Notified: return QStringLiteral("NOTIFIED");
    case State::Downloading: return QStringLiteral("DOWNLOADING");
    case State::Verifying: return QStringLiteral("VERIFYING");
    case State::Writing: return QStringLiteral("WRITING");
    case State::Rebooting: return QStringLiteral("REBOOTING");
    case State::Success: return QStringLiteral("SUCCESS");
    case State::Failed: return QStringLiteral("FAILED");
    case State::RolledBack: return QStringLiteral("ROLLED_BACK");
  }
  return QString();
}

int Updater::progress() const {
  switch (state_) {
    case State::Downloading: return downloader_.progress();
    case State::Verifying: {
      const int total = downloader_.manifest().chunkCount;
      return (check_ && total > 0) ? check_->checkedChunks() * 100 / total : 0;
    }
    case State::Writing:
      return writer_.imageSize() > 0
                 ? static_cast<int>(writer_.written() * 100 / writer_.imageSize())
                 : 0;
    case State::Rebooting:
    case State::Success: return 100;
    default: return 0;
  }
}

QJsonObject Updater::loginFields() const {
  QJsonObject fields;
  // 恢复模式下没有可运行的固件：版本为空串，安全版本号报 0
  fields.insert(QStringLiteral("fw_version"), boot_.hasFirmware ? boot_.running.version : QString());
  fields.insert(QStringLiteral("security_version"),
                boot_.hasFirmware ? boot_.running.securityVersion : 0);
  fields.insert(QStringLiteral("active_slot"), boot_.config.active);
  return fields;
}

}  // namespace fwds
