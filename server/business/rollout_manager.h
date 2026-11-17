// RolloutManager：发布模块（设计第 3 节、4.2 节）。决定“把哪个固件包推给哪台设备”，
// 把每次推送记进发布表，然后交给 ChunkService 去通知设备。
// 目前只实现了最小的一种发布：操作员把一个包下发给一台指定的在线设备。它被记成
// “只有一台手动选定的金丝雀设备、停在灰度阶段的发布”，用的就是完整灰度发布的那两张表，
// 所以后面加上按分组灰度、观察期、确认全量、紧急停止时，表结构不用改。
// 每次推送之前在这里统一裁决（设计 4.2 节的“默认只监控”“互锁”“断网不盲发”）：
//   ① “允许下发”开关已打开            ② 固件在库里且启动检查通过
//   ③ 设备已注册、未停用、在线         ④ 固件的适用型号和设备型号一致
//   ⑤ 设备不在升级途中，也不是刚被下发过还没来得及上报状态
// 版本高低不在这里判断：防降级由设备自己把关（它只信签名保护的版本号和自己的 boot.json），
// 服务端即使下发了旧版本，设备也会拒绝并告警。
// 升级结果要等设备的 RESULT 事件入库（事件补传对账一步）才能回写到发布目标表；
// 在那之前，结果从设备监控页的“升级状态”一列看。
#pragma once

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QObject>

#include "common/config.h"
#include "server/business/chunk_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/firmware_repo.h"
#include "server/storage/database.h"

namespace fwds {

// 发布表和发布目标表连起来的一行，给界面的“下发记录”用。
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

class RolloutManager : public QObject {
  Q_OBJECT
 public:
  RolloutManager(Database* db, const ProtocolParams& params, DeviceRegistry* registry,
                 FirmwareRepo* firmware, ChunkService* chunks, const DispatchGate* gate,
                 QObject* parent = nullptr);

  // 服务端启动时调用：上次运行时还在推送中的发布一律改成“已暂停”（设计 4.7 节“服务端重启”）。
  // 内存里的下发记录已经随进程消失，要继续必须由操作员重新确认，不会自动接着推。
  bool load(QString* error);

  // 最近的下发记录，从新到旧，最多 limit 条。
  QList<DispatchRecord> recentDispatches(int limit) const;

 signals:
  void changed();

 private:
  friend class AdminService;  // 下发是管理操作，只能经 AdminService 调用（先过权限检查）

  // 把 pkgId 下发给一台设备。通过全部裁决才建发布记录并发送 UPDATE_NOTIFY。
  // 被拒时返回 false，error 是可以显示给操作员的原因，数据库和设备都不受影响。
  bool dispatchToDevice(const QString& pkgId, const QString& deviceId, const QString& createdBy,
                        qint64* releaseId, QString* error);

  // 五项裁决，全部通过时把要下发的包放进 package。
  bool checkDispatch(const QString& pkgId, const QString& deviceId, StoredPackage* package,
                     QString* error) const;
  bool insertRelease(const QString& pkgId, const QString& deviceId, const QString& createdBy,
                     qint64* releaseId, QString* error);
  void markDispatchFailed(qint64 releaseId, const QString& deviceId, const QString& reason);

  Database* db_;
  ProtocolParams params_;
  DeviceRegistry* registry_;
  FirmwareRepo* firmware_;
  ChunkService* chunks_;
  const DispatchGate* gate_;
  QHash<QString, QDateTime> lastDispatchAt_;  // 设备 ID → 最近一次向它下发的时间
};

}  // namespace fwds
