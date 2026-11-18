// RolloutManager：发布模块（设计第 3 节、4.2 节）。决定“把哪个固件包、在什么时候、推给哪些设备”，
// 把每一步记进发布表和发布目标表，真正的推送交给 ChunkService。
//
// 一次发布 = 一个固件包 + 一批目标设备，按设计 4.2 节的状态机推进：
//   draft 草稿 ──开始灰度──▶ canary 灰度中 ──金丝雀全部成功──▶ observing 观察期
//   ──观察期内无失败、无告警──▶ awaiting_full 待确认全量 ──确认全量──▶ full 全量推送中
//   ──全部有结果──▶ done 已完成
//   推送阶段出现失败、告警、失败比例超阈值、“允许下发”被关闭、服务端重启 ──▶ paused 已暂停
//   紧急停止、终止 ──▶ aborted 已终止
// 目标设备分两批：phase=canary 是金丝雀（按分组或手动勾选），phase=full 是同型号的其余设备。
// 每台设备的状态：pending 排队 → notified 已通知 → success / failed / rolled_back；
//   held 待确认：轮到它时不在线或正忙，没有推，等操作员确认后再推（断网不盲发）；
//   cancelled：发布终止时还没推的设备。
//
// 推送前的裁决（设计 4.2 节）：
//   发布级  “允许下发”开关已打开；固件可用；同一型号同时只有一个进行中的发布（互锁 ①）；
//           只有“待确认全量”才能确认全量（互锁 ③，未通过灰度不能全量）
//   设备级  已注册、未停用、在线；型号一致；不在升级途中、刚下发过的设备不推（互锁 ②）
// 推送阶段同时“在路上”（notified）的设备不超过发布的并发数 K；一台有了结果再推下一台。
//
// 设备的升级结果、进度、告警由事件入库模块（EventStore）去重入库后，调用 onDeviceResult /
// onDeviceProgress / onDeviceAlert 告诉这里，发布据此推进或暂停。
// 改数据的操作都是私有的，只有 AdminService（先查角色、再核对口令）能调用。
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QObject>
#include <QStringList>

#include "common/config.h"
#include "server/business/chunk_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/firmware_repo.h"
#include "server/security/audit_service.h"
#include "server/storage/database.h"

namespace fwds {

// 发布表和发布目标表连起来的一行，给“固件库”页的下发记录用。
struct DispatchRecord {
  qint64 releaseId = 0;
  QString pkgId;
  QString deviceId;
  QString releaseState;   // 发布状态：canary / paused / aborted ……
  QString targetStatus;   // 这台设备的状态：notified / failed ……
  QString lastError;
  QString createdBy;
  QDateTime createdAt;
};

// 一次发布的概况，给“灰度发布”页的发布列表用。
struct ReleaseInfo {
  qint64 releaseId = 0;
  QString pkgId;
  QString model;          // 固件适用型号
  QString version;        // 固件版本
  QString state;          // draft / canary / observing / awaiting_full / full / paused / done / aborted
  QString canaryGroup;    // 按分组选金丝雀时的分组名；手动勾选时为空
  int concurrency = 0;
  QString createdBy;
  QDateTime createdAt;
  QString note;           // 最近一次自动暂停的原因（只在内存里，重启后为空）
  // 目标设备按状态计数
  int total = 0;
  int canary = 0;         // 其中金丝雀设备数
  int success = 0;
  int failed = 0;         // failed + rolled_back
  int notified = 0;
  int pending = 0;
  int held = 0;
  int cancelled = 0;
};

// 发布里的一台目标设备。
struct TargetInfo {
  QString deviceId;
  QString phase;     // canary / full
  QString status;    // pending / held / notified / success / failed / rolled_back / cancelled
  int progress = 0;
  QString lastError;
  QDateTime updatedAt;
};

class RolloutManager : public QObject {
  Q_OBJECT
 public:
  RolloutManager(Database* db, const ProtocolParams& params, const RolloutParams& rollout,
                 DeviceRegistry* registry, FirmwareRepo* firmware, ChunkService* chunks,
                 const DispatchGate* gate, QObject* parent = nullptr);

  // 审计日志。由 main 设置；没有设置时自动动作只写进程日志。
  void setAuditService(AuditService* audit) { audit_ = audit; }

  // 服务端启动时调用：上次运行时还在推送中的发布一律改成“已暂停”（设计 4.7 节“服务端重启”）。
  // 内存里的下发记录已经随进程消失，要继续必须由操作员确认，不会自动接着推。
  bool load(QString* error);

  // ---- 查询（界面用）----
  QList<ReleaseInfo> releases(int limit) const;
  QList<TargetInfo> targets(qint64 releaseId) const;
  QList<DispatchRecord> recentDispatches(int limit) const;  // 最近的下发记录，从新到旧
  const RolloutParams& params() const { return rollout_; }

  // ---- 设备事件（EventStore 去重入库后调用，每个事件只调一次）----
  // result 为 SUCCESS / FAILED / ROLLED_BACK。releaseId 为 0 时（设备重启后补报，已不知道发布号）
  // 按“设备 + 固件包”找最近的那次发布。
  void onDeviceResult(const QString& deviceId, qint64 releaseId, const QString& pkgId,
                      const QString& result, int code, const QString& detail);
  void onDeviceProgress(const QString& deviceId, const QString& pkgId, const QString& state,
                        int progress);
  // 安全告警（验签失败、降级、哈希不符等）：推送阶段的发布立即暂停。
  void onDeviceAlert(const QString& deviceId, const QString& pkgId, int code,
                     const QString& detail);

 signals:
  void changed();

 private:
  friend class AdminService;  // 下面的操作只能经 AdminService 调用（先过权限检查和口令确认）

  // 发布表的一行。
  struct Release {
    qint64 id = 0;
    QString pkgId;
    QString state;
    int concurrency = 0;
  };
  // 一个阶段（canary / full）里目标设备按状态的计数。
  struct PhaseCount {
    int total = 0, success = 0, failed = 0, notified = 0, pending = 0, held = 0, cancelled = 0;
    bool allFinished() const { return pending == 0 && held == 0 && notified == 0; }
  };

  // ---- 管理操作（AdminService 调用）。被拒时返回 false，error 是给操作员看的原因 ----
  // 单台下发：一条只有一台手动选定的金丝雀设备、直接进入灰度的发布。
  bool dispatchToDevice(const QString& pkgId, const QString& deviceId, const QString& actor,
                        qint64* releaseId, QString* error);
  // 新建发布（草稿）：金丝雀为 canaryDevices，同型号的其余设备进入全量批。
  bool createRelease(const QString& pkgId, const QStringList& canaryDevices,
                     const QString& canaryGroup, int concurrency, const QString& actor,
                     qint64* releaseId, QString* error);
  bool startCanary(qint64 releaseId, const QString& actor, QString* error);   // 草稿 → 灰度中
  bool confirmFull(qint64 releaseId, const QString& actor, QString* error);   // 待确认全量 → 全量
  bool pause(qint64 releaseId, const QString& actor, QString* error);         // 手动暂停
  bool resume(qint64 releaseId, const QString& actor, QString* error);        // 已暂停 → 继续
  bool pushHeld(qint64 releaseId, const QString& actor, QString* error);      // 推送待确认设备
  // 终止：通知中的设备发 UPDATE_CANCEL，还没推的设备记为 cancelled，发布记为已终止。
  // emergency 为 true 是推送阶段的紧急停止，否则是草稿或已暂停时的终止。
  bool abort(qint64 releaseId, const QString& actor, bool emergency, QString* error);

  // ---- 裁决 ----
  bool checkGateAndPackage(const QString& pkgId, StoredPackage* package, QString* error) const;
  // 互锁 ①：同型号是否已有进行中的发布（不算 exceptId 自己）。有则填 error。
  bool checkModelFree(const QString& model, qint64 exceptId, QString* error) const;
  // 设备级裁决：注册、停用、在线、型号、升级途中、刚下发过。
  bool checkDevice(const QString& deviceId, const StoredPackage& package, QString* error) const;

  // ---- 推进 ----
  // 先 evaluate；仍在推送阶段的话，按并发数给当前阶段排队中的设备发通知，不能推的设备记为待确认。
  void pushPending(qint64 releaseId);
  // 看各阶段的计数，决定发布是否进入下一个状态（观察期、已暂停、已完成）。
  void evaluate(qint64 releaseId);
  // 观察期到时：金丝雀设备都在线并且运行着新版本，进入“待确认全量”，否则暂停。
  void finishObservation(qint64 releaseId);
  // 把推送阶段的发布改为已暂停（自动暂停），reason 记进审计日志并在界面显示。
  void autoPause(qint64 releaseId, const QString& reason);

  // ---- 数据库 ----
  bool findRelease(qint64 releaseId, Release* release) const;
  bool setState(qint64 releaseId, const QString& state, QString* error = nullptr);
  bool setTarget(qint64 releaseId, const QString& deviceId, const QString& status,
                 const QString& lastError);
  PhaseCount countPhase(qint64 releaseId, const QString& phase) const;
  QStringList targetsWithStatus(qint64 releaseId, const QString& phase, const QString& status) const;
  bool insertRelease(const QString& pkgId, const QString& state, const QString& canaryGroup,
                     int concurrency, const QString& actor,
                     const QList<QPair<QString, QString>>& targets, qint64* releaseId,
                     QString* error);
  // 写一条 ROLLOUT 分类的审计日志（同时写进程日志）。
  // source 为空时记为本机主机名。
  void record(const QString& actor, const QString& deviceId, const QString& message,
              bool warn = false, const QString& source = QString());

  Database* db_;
  ProtocolParams params_;
  RolloutParams rollout_;
  DeviceRegistry* registry_;
  FirmwareRepo* firmware_;
  ChunkService* chunks_;
  const DispatchGate* gate_;
  AuditService* audit_ = nullptr;
  QHash<QString, QDateTime> lastDispatchAt_;  // 设备 ID → 最近一次向它下发的时间
  QHash<qint64, int> observeRound_;           // 发布号 → 第几次进入观察期（让过期的定时器作废）
  QHash<qint64, QString> notes_;              // 发布号 → 最近一次自动暂停的原因
};

// 发布状态、目标设备状态的中文名（界面和提示信息用）。
QString releaseStateText(const QString& state);
QString targetStatusText(const QString& status);

}  // namespace fwds
