// Updater：设备升级状态机（设计 4.4 节），把一次升级从头管到尾：
//   IDLE → NOTIFIED → DOWNLOADING      交给 Downloader（验签、型号、防降级、分片下载、续传）
//        → VERIFYING                   分片收齐后：整镜像哈希重算一遍，manifest 签名再验一遍
//        → WRITING                     写进非活动分区，写完才在 boot.json 里登记 pending
//        → REBOOTING                   模拟重启：断开连接，跑一遍 Bootloader，再连回去
//        → SUCCESS / ROLLED_BACK       新固件转正，或者没通过自检、已回到旧分区
//   任何一步出错 → FAILED              旧分区没动过，设备照常运行
// 它同时保管“设备现在运行的是什么固件”（Bootloader 的启动结果），LOGIN、心跳和界面都从这里取。
//
// 和 Downloader 一样全程事件驱动：校验和写入都切成小段，由一个间隔为 0 的定时器推着走，
// 每做一段就回到事件循环，所以 256 MB 的镜像也不会让界面停顿，升级途中也能响应取消。
#pragma once

#include <QFile>
#include <QJsonObject>
#include <QObject>
#include <QTimer>
#include <memory>

#include "client/business/bootloader.h"
#include "client/business/downloader.h"
#include "client/security/anti_rollback.h"
#include "client/security/update_validator.h"
#include "client/storage/resume_store.h"
#include "client/storage/slot_store.h"
#include "common/config.h"

namespace fwds {

class Updater : public QObject {
  Q_OBJECT
 public:
  enum class State {
    Idle,
    Notified,
    Downloading,
    Verifying,
    Writing,
    Rebooting,
    Success,     // 最近一次升级成功（下一次通知到来前保持显示）
    Failed,      // 最近一次升级失败，原固件不受影响
    RolledBack,  // 最近一次升级的新固件没能启动，已回滚
  };

  // verifier 里已装好 FSK 公钥，必须比 Updater 活得久。send 由网络层提供（TcpClient::send）。
  Updater(const ClientConfig& config, const ManifestVerifier& verifier, Downloader::SendFn send,
          QObject* parent = nullptr);
  ~Updater() override;

  // 上电：跑一遍 Bootloader，确定运行哪个分区。主程序在连接服务端之前调用一次。
  // 如果上次升级停在“已写入、未确认”（比如重启途中进程被杀），这里会把它走完并报告结果。
  void powerOn();

  // 网络层收到的业务帧和连接状态变化。
  void handleFrame(const fwds::Frame& frame);
  void setOnline(bool online);

  State state() const { return state_; }
  // 协议 6.1 节的状态名和进度（0 ~ 100），心跳里上报。
  QString stateName() const;
  int progress() const;

  // 最近一次启动的结论：运行的固件、活动分区、最小安全版本号。
  const BootResult& bootState() const { return boot_; }
  // LOGIN 里和固件有关的三个字段：fw_version、security_version、active_slot（协议 5.1 节）。
  QJsonObject loginFields() const;

 signals:
  void stateChanged(fwds::Updater::State state);
  void progressChanged(int percent);
  // 安全告警（3001、3003、3004、3005），上报 ALERT 用。
  void alertRaised(int code, const QString& detail);
  // 一次升级有了最终结果。result 是 "SUCCESS"、"FAILED" 或 "ROLLED_BACK"，上报 RESULT 用。
  void finished(const QString& result, int code, const QString& detail);
  // 模拟重启的两端：先请网络层断开连接（BYE reboot），Bootloader 跑完后再请它重新连接。
  void rebootRequested();
  void rebootFinished();

 private:
  void onDownloaderState(Downloader::State state);
  void onDownloadCompleted(const QString& partPath);
  void workStep();    // 定时器每次触发做一小段：VERIFYING 时校验，WRITING 时拷贝
  void verifyStep();
  void startWriting();
  void writeStep();
  void commitWrite();  // 镜像写完：写 manifest、登记 pending、进入 REBOOTING
  void reboot();       // 模拟重启：跑 Bootloader 并报告结果
  void applyBoot();    // 用启动结果更新防降级的基准
  void failInstall(ErrorCode code, const QString& detail, bool alert, bool discardDownload);
  bool installing() const {
    return state_ == State::Verifying || state_ == State::Writing || state_ == State::Rebooting;
  }
  void setState(State state);
  void reportProgress();

  ClientConfig config_;
  const ManifestVerifier& verifier_;
  Downloader::SendFn send_;

  // 下面几个成员的先后顺序就是构造顺序：后面的要用到前面的
  Bootloader bootloader_;
  SlotStore slots_;
  DeviceAntiRollback antiRollback_;
  UpdateValidator validator_;
  ResumeStore store_;
  Downloader downloader_;

  State state_ = State::Idle;
  BootResult boot_;
  int lastPercent_ = -1;

  QTimer workTimer_;                    // 间隔为 0：每回到事件循环一次做一小段
  QFile part_;                          // 下载好的镜像（VERIFYING 时读）
  std::unique_ptr<ImageCheck> check_;   // 整镜像核对的进度
  SlotWriter writer_;                   // 写分区的进度
  QString targetSlot_;                  // 本次写入哪个分区
  // 本次运行中因为启动失败被回滚的包。服务端在设备重新登录后会把同一个包的通知再发一次，
  // 不记住的话设备会一遍遍地写入、重启、回滚
  QString rolledBackPkgId_;
};

}  // namespace fwds
