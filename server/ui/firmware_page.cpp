#include "server/ui/firmware_page.h"

#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include "server/ui/login_dialog.h"

namespace fwds {

namespace {

enum FirmwareColumn { ColModel, ColVersion, ColSecurityVersion, ColSize, ColImportedBy, ColImportedAt, ColCheck, ColCount };
enum DispatchColumn { DisRelease, DisTime, DisDevice, DisFirmware, DisBy, DisState, DisCount };

constexpr int kDispatchRows = 50;  // 下发记录最多显示的条数

QString localTime(const QDateTime& utc) {
  return utc.isValid() ? utc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                       : QStringLiteral("—");
}

// 一张只读、整行选中的表格，两个列表共用这套设置。
QTableWidget* makeTable(const QStringList& headers, QWidget* parent) {
  auto* table = new QTableWidget(0, static_cast<int>(headers.size()), parent);
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->verticalHeader()->setVisible(false);
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  table->horizontalHeader()->setStretchLastSection(true);
  return table;
}

// 下发记录的状态一列：设备的状态，加上说明（失败原因、待确认的原因等）。
QString dispatchStateText(const DispatchRecord& r) {
  QString text = targetStatusText(r.targetStatus);
  if (r.releaseState == QLatin1String("paused") || r.releaseState == QLatin1String("aborted")) {
    text += QStringLiteral("（发布%1）").arg(releaseStateText(r.releaseState));
  }
  if (!r.lastError.isEmpty()) text += QStringLiteral("：") + r.lastError;
  return text;
}

}  // namespace

FirmwarePage::FirmwarePage(FirmwareRepo* firmware, RolloutManager* rollout,
                           DeviceRegistry* registry, AdminService* admin, QWidget* parent)
    : QWidget(parent), firmware_(firmware), rollout_(rollout), registry_(registry), admin_(admin) {
  // ---- 按钮和验签公钥指纹 ----
  importButton_ = new QPushButton(QStringLiteral("导入固件包…"), this);
  dispatchButton_ = new QPushButton(QStringLiteral("下发到设备…"), this);
  // 指纹显示出来，维护员可以和签发工具 fsk-init 显示的值核对：服务端认的是不是那一把公钥
  auto* fingerprint = new QLabel(
      QStringLiteral("验签公钥（FSK）指纹：%1").arg(firmware_->fskFingerprint()), this);
  fingerprint->setTextInteractionFlags(Qt::TextSelectableByMouse);
  auto* buttons = new QHBoxLayout;
  buttons->addWidget(importButton_);
  buttons->addWidget(dispatchButton_);
  buttons->addStretch();
  buttons->addWidget(fingerprint);
  connect(importButton_, &QPushButton::clicked, this, &FirmwarePage::importPackage);
  connect(dispatchButton_, &QPushButton::clicked, this, &FirmwarePage::dispatchSelected);

  // ---- 固件列表和详情 ----
  table_ = makeTable({QStringLiteral("型号"), QStringLiteral("版本"), QStringLiteral("安全版本号"),
                      QStringLiteral("镜像大小"), QStringLiteral("导入人"), QStringLiteral("导入时间"),
                      QStringLiteral("服务端检查")},
                     this);
  detail_ = new QTextEdit(this);
  detail_->setReadOnly(true);
  auto* upper = new QSplitter(Qt::Horizontal, this);
  upper->addWidget(table_);
  upper->addWidget(detail_);
  upper->setStretchFactor(0, 3);
  upper->setStretchFactor(1, 2);
  connect(table_, &QTableWidget::itemSelectionChanged, this, &FirmwarePage::showDetail);

  // ---- 下发记录 ----
  dispatches_ = makeTable({QStringLiteral("发布号"), QStringLiteral("时间"), QStringLiteral("设备"),
                           QStringLiteral("固件"), QStringLiteral("操作人"), QStringLiteral("状态")},
                          this);
  dispatches_->setSelectionMode(QAbstractItemView::NoSelection);
  auto* lower = new QWidget(this);
  auto* lowerLayout = new QVBoxLayout(lower);
  lowerLayout->setContentsMargins(0, 0, 0, 0);
  lowerLayout->addWidget(new QLabel(QStringLiteral("下发记录（最新的在最上面）"), lower));
  lowerLayout->addWidget(dispatches_);

  auto* splitter = new QSplitter(Qt::Vertical, this);
  splitter->addWidget(upper);
  splitter->addWidget(lower);
  splitter->setStretchFactor(0, 3);
  splitter->setStretchFactor(1, 2);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(buttons);
  layout->addWidget(splitter);

  connect(firmware_, &FirmwareRepo::changed, this, &FirmwarePage::refreshFirmware);
  connect(rollout_, &RolloutManager::changed, this, &FirmwarePage::refreshDispatches);
  refreshFirmware();
  refreshDispatches();
  applyPermissions();
}

void FirmwarePage::applyPermissions() {
  // 第一道权限检查：没有权限的按钮不出现。第二道在 AdminService 里
  importButton_->setVisible(admin_->can(Permission::ImportFirmware));
  dispatchButton_->setVisible(admin_->can(Permission::ManageRelease));
  showDetail();
}

QString FirmwarePage::selectedPkgId() const {
  const int row = table_->currentRow();
  if (row < 0 || !table_->item(row, 0)) return QString();
  return table_->item(row, 0)->data(Qt::UserRole).toString();  // 包 ID 藏在第一列的 UserRole 里
}

void FirmwarePage::refreshFirmware() {
  const QString keep = selectedPkgId();
  const QList<StoredPackage> packages = firmware_->packages();
  table_->setRowCount(static_cast<int>(packages.size()));
  int selectRow = packages.isEmpty() ? -1 : 0;
  for (int row = 0; row < packages.size(); ++row) {
    const StoredPackage& p = packages.at(row);
    const Manifest& m = p.manifest;
    const QStringList cells = {
        m.deviceModel,
        m.version,
        QString::number(m.securityVersion),
        QLocale().formattedDataSize(m.imageSize),
        p.importedBy,
        localTime(p.importedAt),
        p.usable ? QStringLiteral("✔ 验签与哈希通过") : QStringLiteral("✘ 不可用：") + p.problem};
    for (int col = 0; col < ColCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (!p.usable) item->setForeground(QColor(0xb0, 0x00, 0x20));  // 不可用的包整行标红
      table_->setItem(row, col, item);
    }
    table_->item(row, 0)->setData(Qt::UserRole, m.pkgId);
    if (m.pkgId == keep) selectRow = row;
  }
  if (selectRow >= 0) table_->selectRow(selectRow);
  showDetail();
}

void FirmwarePage::showDetail() {
  StoredPackage p;
  const bool selected = firmware_->find(selectedPkgId(), &p);
  dispatchButton_->setEnabled(selected && p.usable);
  if (!selected) {
    detail_->setPlainText(QStringLiteral("固件库是空的。维护员用“导入固件包…”导入签发工具生成的 .fwpkg。"));
    return;
  }
  const Manifest& m = p.manifest;
  QStringList lines = {
      QStringLiteral("包 ID：%1").arg(m.pkgId),
      QStringLiteral("适用型号：%1").arg(m.deviceModel),
      QStringLiteral("版本：%1　　安全版本号：%2").arg(m.version).arg(m.securityVersion),
      QStringLiteral("镜像大小：%1 字节").arg(m.imageSize),
      QStringLiteral("整镜像 SHA-256：%1").arg(QString::fromLatin1(m.imageSha256.toHex())),
  };
  if (p.usable) {
    lines += {
        QStringLiteral("分片：%1 片 × %2 字节").arg(m.chunkCount).arg(m.chunkSize),
        QStringLiteral("签发时间：%1").arg(m.buildTime),
        QStringLiteral("发布说明：%1").arg(m.releaseNote.isEmpty() ? QStringLiteral("—") : m.releaseNote),
        QString(),
        QStringLiteral("服务端检查结果"),
        QStringLiteral("  ✔ manifest 签名：RSA-3072-PSS-SHA256 验签通过"),
        QStringLiteral("  ✔ 分片哈希：%1 片全部与 manifest 一致").arg(m.chunkCount),
        QStringLiteral("  ✔ 整镜像哈希：与 manifest 一致"),
        QStringLiteral("以上检查在导入时和每次服务端启动时各做一遍；设备收到后还会自己再验，不依赖这里的结论。"),
    };
  } else {
    lines += {QString(), QStringLiteral("✘ 不可用：%1").arg(p.problem),
              QStringLiteral("这个包在服务端启动时的重新检查中没有通过，不能下发。")};
  }
  lines += {QString(), QStringLiteral("库内文件：%1").arg(p.filePath)};
  detail_->setPlainText(lines.join(QLatin1Char('\n')));
}

void FirmwarePage::refreshDispatches() {
  const QList<DispatchRecord> records = rollout_->recentDispatches(kDispatchRows);
  dispatches_->setRowCount(static_cast<int>(records.size()));
  for (int row = 0; row < records.size(); ++row) {
    const DispatchRecord& r = records.at(row);
    // 固件一列显示“型号 版本”；包已经不在库里时退回显示包 ID
    StoredPackage p;
    const QString firmwareText =
        firmware_->find(r.pkgId, &p)
            ? QStringLiteral("%1 %2").arg(p.manifest.deviceModel, p.manifest.version)
            : r.pkgId;
    const QStringList cells = {QString::number(r.releaseId), localTime(r.createdAt), r.deviceId,
                               firmwareText, r.createdBy, dispatchStateText(r)};
    for (int col = 0; col < DisCount; ++col) {
      dispatches_->setItem(row, col, new QTableWidgetItem(cells.at(col)));
    }
  }
}

void FirmwarePage::importPackage() {
  const QString path = QFileDialog::getOpenFileName(
      this, QStringLiteral("选择固件包"), QString(), QStringLiteral("固件包 (*.fwpkg);;所有文件 (*)"));
  if (path.isEmpty()) return;
  // 整包检查要把镜像读两遍（复制一遍、算哈希一遍），大文件需要几秒钟，这期间显示等待光标
  QString error;
  QApplication::setOverrideCursor(Qt::WaitCursor);
  const bool ok = admin_->importFirmware(path, &error);
  QApplication::restoreOverrideCursor();
  if (!ok) {
    QMessageBox::warning(this, QStringLiteral("导入固件包"),
                         QStringLiteral("没有导入，固件库不变。\n原因：%1").arg(error));
  }
}

void FirmwarePage::dispatchSelected() {
  StoredPackage p;
  if (!firmware_->find(selectedPkgId(), &p)) return;
  const Manifest& m = p.manifest;

  // 候选设备：在线、未停用、型号和固件一致。其余条件（开关、互锁）由业务层裁决并给出原因
  QDialog dialog(this);
  dialog.setWindowTitle(QStringLiteral("下发到设备"));
  dialog.setMinimumWidth(460);
  auto* deviceBox = new QComboBox(&dialog);
  const QList<DeviceRecord> devices = registry_->devices();
  for (const DeviceRecord& d : devices) {
    if (!d.online || d.disabled || d.model != m.deviceModel) continue;
    deviceBox->addItem(QStringLiteral("%1（当前 %2，安全版本号 %3）")
                           .arg(d.deviceId, d.currentVersion.isEmpty() ? QStringLiteral("无固件")
                                                                       : d.currentVersion)
                           .arg(d.securityVersion),
                       d.deviceId);
  }
  if (deviceBox->count() == 0) {
    QMessageBox::information(this, QStringLiteral("下发到设备"),
                             QStringLiteral("没有在线的 %1 设备。离线设备不下发。").arg(m.deviceModel));
    return;
  }
  auto* form = new QFormLayout(&dialog);
  form->addRow(QStringLiteral("固件"),
               new QLabel(QStringLiteral("%1 %2（安全版本号 %3）")
                              .arg(m.deviceModel, m.version)
                              .arg(m.securityVersion),
                          &dialog));
  form->addRow(QStringLiteral("目标设备"), deviceBox);
  auto* box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  box->button(QDialogButtonBox::Ok)->setText(QStringLiteral("下发"));
  box->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  form->addRow(box);
  connect(box, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(box, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  if (dialog.exec() != QDialog::Accepted) return;
  const QString deviceId = deviceBox->currentData().toString();

  // 推送固件是对现场设备的写操作：重新输入口令确认（二次确认）
  SecureBuffer password;
  if (!askConfirmPassword(this, QStringLiteral("下发到设备"),
                          QStringLiteral("向 %1 下发 %2 %3。\n设备验签通过后会下载、写入备用分区并重启。")
                              .arg(deviceId, m.deviceModel, m.version),
                          &password)) {
    return;
  }
  QString error;
  if (!admin_->dispatchFirmware(m.pkgId, deviceId, password, &error)) {
    QMessageBox::warning(this, QStringLiteral("下发到设备"), QStringLiteral("没有下发。\n原因：%1").arg(error));
  }
  refreshDispatches();  // 被拒的下发不改数据库，但“设备刚好离线”那种情况会留下一条记录
}

}  // namespace fwds
