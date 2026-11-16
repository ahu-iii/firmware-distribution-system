#include "server/ui/device_page.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QSplitter>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QVBoxLayout>

#include "common/log.h"
#include "server/ui/device_table_model.h"

namespace fwds {

namespace {

constexpr int kMaxEventLines = 200;            // 告警列表最多保留的条数
constexpr qint64 kMaxCertFileSize = 64 * 1024;  // 证书文件只有一两 KB，超过这个大小不读

// 进度列画成进度条。没有进度（-1）时什么都不画。
class ProgressDelegate : public QStyledItemDelegate {
 public:
  using QStyledItemDelegate::QStyledItemDelegate;

  void paint(QPainter* painter, const QStyleOptionViewItem& option,
             const QModelIndex& index) const override {
    QStyledItemDelegate::paint(painter, option, index);  // 先画背景（选中、告警底色）
    const int progress = index.data(Qt::UserRole).toInt();
    if (progress < 0) return;
    QStyleOptionProgressBar bar;
    bar.rect = option.rect.adjusted(4, 4, -4, -4);
    bar.minimum = 0;
    bar.maximum = 100;
    bar.progress = progress;
    bar.text = QStringLiteral("%1%").arg(progress);
    bar.textVisible = true;
    bar.textAlignment = Qt::AlignCenter;
    bar.state = QStyle::State_Enabled | QStyle::State_Horizontal;
    QApplication::style()->drawControl(QStyle::CE_ProgressBar, &bar, painter);
  }
};

}  // namespace

DevicePage::DevicePage(DeviceRegistry* registry, AdminService* admin, QWidget* parent)
    : QWidget(parent), registry_(registry), admin_(admin) {
  // ---- 管理按钮（维护员）----
  registerButton_ = new QPushButton(QStringLiteral("注册设备…"), this);
  disableButton_ = new QPushButton(QStringLiteral("停用"), this);
  groupButton_ = new QPushButton(QStringLiteral("修改分组…"), this);
  auto* buttons = new QHBoxLayout;
  buttons->addWidget(registerButton_);
  buttons->addWidget(disableButton_);
  buttons->addWidget(groupButton_);
  buttons->addStretch();
  connect(registerButton_, &QPushButton::clicked, this, &DevicePage::registerDevice);
  connect(disableButton_, &QPushButton::clicked, this, &DevicePage::toggleDisabled);
  connect(groupButton_, &QPushButton::clicked, this, &DevicePage::changeGroup);

  // ---- 设备表 ----
  model_ = new DeviceTableModel(registry_, this);
  table_ = new QTableView(this);
  table_->setModel(model_);
  table_->setItemDelegateForColumn(DeviceTableModel::ColProgress, new ProgressDelegate(table_));
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->verticalHeader()->setVisible(false);
  table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setSectionResizeMode(DeviceTableModel::ColProgress,
                                                   QHeaderView::Stretch);
  table_->horizontalHeader()->setMinimumSectionSize(70);
  connect(table_->selectionModel(), &QItemSelectionModel::selectionChanged, this,
          &DevicePage::updateButtons);
  connect(model_, &QAbstractItemModel::dataChanged, this, &DevicePage::updateButtons);
  connect(model_, &QAbstractItemModel::modelReset, this, &DevicePage::updateButtons);

  // ---- 安全告警与操作记录 ----
  events_ = new QListWidget(this);
  events_->setSelectionMode(QAbstractItemView::NoSelection);
  auto* eventsBox = new QWidget(this);
  auto* eventsLayout = new QVBoxLayout(eventsBox);
  eventsLayout->setContentsMargins(0, 0, 0, 0);
  eventsLayout->addWidget(new QLabel(QStringLiteral("安全告警与操作记录（最新的在最上面）"), eventsBox));
  eventsLayout->addWidget(events_);
  connect(logBus(), &LogBus::event, this, &DevicePage::appendEvent);

  auto* splitter = new QSplitter(Qt::Vertical, this);
  splitter->addWidget(table_);
  splitter->addWidget(eventsBox);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 1);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(buttons);
  layout->addWidget(splitter);

  applyPermissions();
}

void DevicePage::applyPermissions() {
  const bool manage = admin_->can(Permission::ManageDevices);
  registerButton_->setVisible(manage);
  disableButton_->setVisible(manage);
  groupButton_->setVisible(manage);
  updateButtons();
}

QString DevicePage::selectedDeviceId() const {
  const QModelIndexList rows = table_->selectionModel()->selectedRows();
  return rows.isEmpty() ? QString() : model_->deviceIdAt(rows.first().row());
}

void DevicePage::updateButtons() {
  DeviceRecord d;
  const bool selected = registry_->find(selectedDeviceId(), &d);
  disableButton_->setEnabled(selected);
  groupButton_->setEnabled(selected);
  disableButton_->setText(selected && d.disabled ? QStringLiteral("启用") : QStringLiteral("停用"));
}

void DevicePage::registerDevice() {
  // 一个小对话框：选设备证书文件，填型号和分组。设备 ID 和指纹从证书里取，不手工输入。
  QDialog dialog(this);
  dialog.setWindowTitle(QStringLiteral("注册设备"));
  dialog.setMinimumWidth(460);
  auto* certPath = new QLineEdit(&dialog);
  auto* browse = new QPushButton(QStringLiteral("选择…"), &dialog);
  auto* certRow = new QHBoxLayout;
  certRow->addWidget(certPath);
  certRow->addWidget(browse);
  auto* modelEdit = new QLineEdit(&dialog);
  auto* groupEdit = new QLineEdit(&dialog);
  modelEdit->setMaxLength(32);
  groupEdit->setMaxLength(32);
  groupEdit->setPlaceholderText(QStringLiteral("可不填，例如 canary"));
  auto* form = new QFormLayout(&dialog);
  form->addRow(QStringLiteral("设备证书（PEM）"), certRow);
  form->addRow(QStringLiteral("型号"), modelEdit);
  form->addRow(QStringLiteral("分组"), groupEdit);
  auto* box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  box->button(QDialogButtonBox::Ok)->setText(QStringLiteral("注册"));
  box->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  form->addRow(box);
  connect(browse, &QPushButton::clicked, &dialog, [&dialog, certPath]() {
    const QString file = QFileDialog::getOpenFileName(
        &dialog, QStringLiteral("选择设备证书"), QString(), QStringLiteral("证书 (*.pem);;所有文件 (*)"));
    if (!file.isEmpty()) certPath->setText(file);
  });
  connect(box, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(box, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  if (dialog.exec() != QDialog::Accepted) return;

  QFile file(certPath->text().trimmed());
  if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxCertFileSize) {
    QMessageBox::warning(this, QStringLiteral("注册设备"), QStringLiteral("证书文件打不开或过大"));
    return;
  }
  QString error;
  if (!admin_->registerDevice(file.readAll(), modelEdit->text(), groupEdit->text(), &error)) {
    QMessageBox::warning(this, QStringLiteral("注册设备"), error);
  }
}

void DevicePage::toggleDisabled() {
  DeviceRecord d;
  if (!registry_->find(selectedDeviceId(), &d)) return;
  const bool disable = !d.disabled;
  if (disable) {
    // 停用会立刻断开设备的连接并拒绝它再登录，先确认一次
    const auto answer = QMessageBox::question(
        this, QStringLiteral("停用设备"),
        QStringLiteral("停用 %1？\n它现有的连接会立即断开，之后登录会被拒绝。").arg(d.deviceId));
    if (answer != QMessageBox::Yes) return;
  }
  QString error;
  if (!admin_->setDeviceDisabled(d.deviceId, disable, &error)) {
    QMessageBox::warning(this, QStringLiteral("停用 / 启用设备"), error);
  }
}

void DevicePage::changeGroup() {
  DeviceRecord d;
  if (!registry_->find(selectedDeviceId(), &d)) return;
  bool ok = false;
  const QString group = QInputDialog::getText(
      this, QStringLiteral("修改分组"), QStringLiteral("%1 的分组（留空表示不分组）").arg(d.deviceId),
      QLineEdit::Normal, d.groupTag, &ok);
  if (!ok) return;
  QString error;
  if (!admin_->setDeviceGroup(d.deviceId, group, &error)) {
    QMessageBox::warning(this, QStringLiteral("修改分组"), error);
  }
}

void DevicePage::appendEvent(const QString& time, bool alert, const QString& text) {
  auto* item = new QListWidgetItem(QStringLiteral("%1  %2").arg(time, text));
  if (alert) item->setForeground(QColor(0xb0, 0x00, 0x20));  // 安全告警标红
  events_->insertItem(0, item);
  while (events_->count() > kMaxEventLines) delete events_->takeItem(events_->count() - 1);
}

}  // namespace fwds
