// DeviceTableModel：设备监控表格的数据模型（设计第 6 节“设备监控”页）。
// 数据全部来自 DeviceRegistry：注册表发 deviceChanged 信号，这里通知表格重画那一行。
// 显示规则：离线行灰色，有告警的行红底，已停用的设备标明“已停用”。
#pragma once

#include <QAbstractTableModel>
#include <QStringList>

#include "server/business/device_registry.h"

namespace fwds {

class DeviceTableModel : public QAbstractTableModel {
  Q_OBJECT
 public:
  enum Column {
    ColDeviceId,
    ColAddress,
    ColOnline,
    ColLogin,
    ColHeartbeat,
    ColVersion,
    ColModel,
    ColGroup,
    ColUpgradeState,
    ColProgress,
    ColEventAck,
    ColCertExpiry,
    ColCount,
  };

  explicit DeviceTableModel(DeviceRegistry* registry, QObject* parent = nullptr);

  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index, int role) const override;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

  // 第 row 行是哪台设备。
  QString deviceIdAt(int row) const { return ids_.value(row); }

 private:
  void reload();                               // 设备增加时整表重排
  void onDeviceChanged(const QString& deviceId);  // 单台设备变化时只刷新一行

  DeviceRegistry* registry_;
  QStringList ids_;  // 每一行对应的设备 ID，按 ID 排序
};

}  // namespace fwds
