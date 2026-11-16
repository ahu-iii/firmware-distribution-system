#include "server/ui/device_table_model.h"

#include <QBrush>
#include <QColor>

namespace fwds {

namespace {

// 证书到期前多少天开始提醒（设计 11.4 节）
constexpr int kCertExpiryWarnDays = 15;

QString localTime(const QDateTime& utc) {
  return utc.isValid() ? utc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                       : QStringLiteral("—");
}

bool certExpiringSoon(const DeviceRecord& d) {
  return d.certNotAfter.isValid() &&
         QDateTime::currentDateTimeUtc().daysTo(d.certNotAfter) < kCertExpiryWarnDays;
}

}  // namespace

DeviceTableModel::DeviceTableModel(DeviceRegistry* registry, QObject* parent)
    : QAbstractTableModel(parent), registry_(registry) {
  connect(registry_, &DeviceRegistry::deviceAdded, this, &DeviceTableModel::reload);
  connect(registry_, &DeviceRegistry::deviceChanged, this, &DeviceTableModel::onDeviceChanged);
  reload();
}

void DeviceTableModel::reload() {
  beginResetModel();
  ids_.clear();
  const QList<DeviceRecord> all = registry_->devices();
  for (const DeviceRecord& d : all) ids_.append(d.deviceId);
  endResetModel();
}

void DeviceTableModel::onDeviceChanged(const QString& deviceId) {
  const int row = static_cast<int>(ids_.indexOf(deviceId));
  if (row < 0) return;
  emit dataChanged(index(row, 0), index(row, ColCount - 1));
}

int DeviceTableModel::rowCount(const QModelIndex& parent) const {
  return parent.isValid() ? 0 : static_cast<int>(ids_.size());
}

int DeviceTableModel::columnCount(const QModelIndex& parent) const {
  return parent.isValid() ? 0 : ColCount;
}

QVariant DeviceTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
  switch (section) {
    case ColDeviceId: return QStringLiteral("设备 ID");
    case ColAddress: return QStringLiteral("IP 地址");
    case ColOnline: return QStringLiteral("在线");
    case ColLogin: return QStringLiteral("登录状态");
    case ColHeartbeat: return QStringLiteral("最后心跳");
    case ColVersion: return QStringLiteral("固件版本");
    case ColModel: return QStringLiteral("型号");
    case ColGroup: return QStringLiteral("分组");
    case ColUpgradeState: return QStringLiteral("升级状态");
    case ColProgress: return QStringLiteral("进度");
    case ColEventAck: return QStringLiteral("事件序号");
    case ColCertExpiry: return QStringLiteral("证书到期");
  }
  return QVariant();
}

QVariant DeviceTableModel::data(const QModelIndex& index, int role) const {
  DeviceRecord d;
  if (!index.isValid() || !registry_->find(ids_.value(index.row()), &d)) return QVariant();

  if (role == Qt::DisplayRole) {
    switch (index.column()) {
      case ColDeviceId: return d.deviceId;
      case ColAddress: return d.online ? d.peerAddress : QStringLiteral("—");
      case ColOnline: return d.online ? QStringLiteral("● 在线") : QStringLiteral("○ 离线");
      case ColLogin:
        if (!d.alert.isEmpty()) return d.alert;
        if (d.disabled) return QStringLiteral("已停用");
        return d.online ? QStringLiteral("已登录") : QStringLiteral("未登录");
      case ColHeartbeat: return localTime(d.lastHeartbeat);
      case ColVersion:
        return d.currentVersion.isEmpty()
                   ? QStringLiteral("—")
                   : QStringLiteral("%1（sv %2）").arg(d.currentVersion).arg(d.securityVersion);
      case ColModel: return d.model;
      case ColGroup: return d.groupTag.isEmpty() ? QStringLiteral("—") : d.groupTag;
      case ColUpgradeState:
        return d.online && !d.upgradeState.isEmpty() ? d.upgradeState : QStringLiteral("—");
      case ColProgress: return QVariant();  // 进度条由 ProgressDelegate 根据 UserRole 画
      case ColEventAck: return d.eventAck;
      case ColCertExpiry:
        return d.certNotAfter.toLocalTime().toString(QStringLiteral("yyyy-MM-dd")) +
               (certExpiringSoon(d) ? QStringLiteral("（即将到期）") : QString());
    }
  }
  // 进度百分比，-1 表示没有进度可显示
  if (role == Qt::UserRole && index.column() == ColProgress) return d.online ? d.progress : -1;

  if (role == Qt::BackgroundRole && !d.alert.isEmpty()) return QBrush(QColor(0xff, 0xd6, 0xd6));
  if (role == Qt::ForegroundRole) {
    if (!d.alert.isEmpty()) return QBrush(QColor(0xb0, 0x00, 0x20));  // 告警行红色
    if (!d.online) return QBrush(QColor(0x8a, 0x8a, 0x8a));           // 离线行灰色
    if (index.column() == ColOnline) return QBrush(QColor(0x1b, 0x7f, 0x3b));
    if (index.column() == ColCertExpiry && certExpiringSoon(d)) {
      return QBrush(QColor(0xb2, 0x6a, 0x00));
    }
  }
  if (role == Qt::ToolTipRole && index.column() == ColDeviceId) {
    return QStringLiteral("证书指纹（SHA-256）：%1").arg(d.certFingerprint);
  }
  return QVariant();
}

}  // namespace fwds
