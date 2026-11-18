// DeviceRegistry：设备注册表（设计第 3 节、5.1 节 DEVICE 表）。
//   注册    维护员导入设备证书，记下设备 ID、型号、分组和证书的 SHA-256 指纹
//   登录    核对 已注册 / 未停用 / 证书指纹一致，任一不符登录处理返回 2005
//   状态    在线与登录状态、最后心跳、版本、升级状态，供设备监控界面显示
// 全部设备在内存里有一份缓存（界面每次刷新都要读，设备数量最多几百台），
// 会影响下次启动的字段同时写数据库。改动注册表的函数（注册、停用、改分组）是私有的，
// 只有 AdminService 能调，它先检查当前登录账号的角色。
#pragma once

#include <QDateTime>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

#include "server/storage/database.h"

namespace fwds {

struct DeviceRecord {
  // ---- 存在数据库里 ----
  QString deviceId;
  QString model;
  QString groupTag;          // 分组标签，灰度发布按它选金丝雀组
  bool disabled = false;     // 已停用：拒绝登录
  QString certFingerprint;   // 设备证书 SHA-256 指纹（小写十六进制）
  QDateTime certNotAfter;    // 设备证书到期时间，界面做到期提醒
  QString currentVersion;    // 设备上次登录时上报的固件版本
  int securityVersion = 0;
  QDateTime lastHeartbeat;   // 登录和下线时写库，在线期间只更新内存
  qint64 eventAck = 0;       // 已连续收到的最大事件序号（EventStore 推进）
  // ---- 只在内存里，服务端重启后从头开始 ----
  bool online = false;       // 在线且已登录
  QString peerAddress;       // 当前连接的对端地址
  QString upgradeState;      // 心跳里上报的升级状态
  int progress = -1;         // 升级进度百分比，-1 表示没有
  QString alert;             // 最近一次告警的说明，非空时界面把这一行标红；登录成功后清除
};

// 登录时对注册表的检查结果。对设备统一返回 2005，具体原因只写服务端日志（协议 5.2 节）。
enum class DeviceCheck { Ok, NotRegistered, Disabled, FingerprintMismatch };

class DeviceRegistry : public QObject {
  Q_OBJECT
 public:
  explicit DeviceRegistry(Database* db, QObject* parent = nullptr);

  // 从数据库读入全部设备。服务端刚启动时没有任何连接，所以把所有设备置为离线。
  bool load(QString* error);

  // ---- 查询 ----
  QList<DeviceRecord> devices() const { return devices_.values(); }  // 按设备 ID 排序
  bool find(const QString& deviceId, DeviceRecord* record) const;
  int onlineCount() const;

  // ---- 登录与在线状态（LoginHandler、HeartbeatMonitor 调用）----
  DeviceCheck checkLogin(const QString& deviceId, const QString& certFingerprint) const;
  void markOnline(const QString& deviceId, const QString& peerAddress, const QString& fwVersion,
                  int securityVersion);
  void markHeartbeat(const QString& deviceId, const QString& upgradeState, int progress);
  void markOffline(const QString& deviceId);
  void raiseAlert(const QString& deviceId, const QString& text);

  // ---- 事件（EventStore 调用）----
  // PROGRESS 事件里的升级状态和进度，比心跳更及时。只更新内存，不动最后心跳时间。
  void markProgress(const QString& deviceId, const QString& upgradeState, int progress);
  // event_ack 推进之后同步内存里的值。数据库里的 event_ack 由 EventStore 和事件在同一个事务里写。
  void noteEventAck(const QString& deviceId, qint64 eventAck);

 signals:
  void deviceAdded(const QString& deviceId);
  void deviceChanged(const QString& deviceId);
  // 设备被停用：HeartbeatMonitor 收到后立即断开它现有的连接（设计 11.4 节）。
  void deviceDisabled(const QString& deviceId);

 private:
  friend class AdminService;  // 下面三个函数只能经 AdminService 调用（先过权限检查）

  // 注册新设备；设备已存在时更新型号、分组和证书指纹（证书轮换），其余字段不动。
  bool addOrUpdateDevice(const DeviceRecord& record, QString* error);
  bool setDisabled(const QString& deviceId, bool disabled, QString* error);
  bool setGroup(const QString& deviceId, const QString& groupTag, QString* error);

  Database* db_;
  QMap<QString, DeviceRecord> devices_;
};

}  // namespace fwds
