#include "server/ui/release_page.h"

#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSet>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include "server/ui/login_dialog.h"

namespace fwds {

namespace {

enum ReleaseColumn { RelId, RelFirmware, RelState, RelCanary, RelCounts, RelConcurrency, RelBy, RelTime, RelNote, RelCount };
enum TargetColumn { TgtDevice, TgtPhase, TgtStatus, TgtProgress, TgtNote, TgtTime, TgtCount };

constexpr int kReleaseRows = 100;  // 发布列表最多显示的条数

QString localTime(const QDateTime& utc) {
  return utc.isValid() ? utc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss"))
                       : QStringLiteral("—");
}

QTableWidget* makeTable(const QStringList& headers, QWidget* parent) {
  auto* table = new QTableWidget(0, static_cast<int>(headers.size()), parent);
  table->setHorizontalHeaderLabels(headers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->verticalHeader()->setVisible(false);
  // 列宽在每次重填后按内容调整一次（见 BUG-009），不用 ResizeToContents：
  // 那样每改一个格子都要把整列重新量一遍，进度事件一多界面就卡
  table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  table->horizontalHeader()->setStretchLastSection(true);
  return table;
}

// 重填后按内容调整列宽。最后一列不调：它是拉伸列，单独调整会让它不再填满表格
void fitColumns(QTableWidget* table) {
  for (int col = 0; col + 1 < table->columnCount(); ++col) table->resizeColumnToContents(col);
}

// 状态的颜色：暂停、终止标红，完成标绿，其余默认。
QColor stateColor(const QString& state) {
  if (state == QLatin1String("paused") || state == QLatin1String("aborted") ||
      state == QLatin1String("failed") || state == QLatin1String("rolled_back")) {
    return QColor(0xb0, 0x00, 0x20);
  }
  if (state == QLatin1String("held")) return QColor(0xb2, 0x6a, 0x00);
  if (state == QLatin1String("done") || state == QLatin1String("success")) return QColor(0x1b, 0x7f, 0x3b);
  return QColor();
}

}  // namespace

ReleasePage::ReleasePage(RolloutManager* rollout, FirmwareRepo* firmware, DeviceRegistry* registry,
                         AdminService* admin, QWidget* parent)
    : QWidget(parent), rollout_(rollout), firmware_(firmware), registry_(registry), admin_(admin) {
  // ---- 按钮 ----
  createButton_ = new QPushButton(QStringLiteral("新建发布…"), this);
  startButton_ = new QPushButton(QStringLiteral("开始灰度"), this);
  fullButton_ = new QPushButton(QStringLiteral("确认全量"), this);
  pauseButton_ = new QPushButton(QStringLiteral("暂停"), this);
  resumeButton_ = new QPushButton(QStringLiteral("继续"), this);
  heldButton_ = new QPushButton(QStringLiteral("推送待确认设备"), this);
  terminateButton_ = new QPushButton(QStringLiteral("终止"), this);
  stopButton_ = new QPushButton(QStringLiteral("■ 紧急停止"), this);
  stopButton_->setStyleSheet(QStringLiteral(
      "QPushButton { background: #b00020; color: white; font-weight: bold; padding: 4px 14px; }"
      "QPushButton:disabled { background: #d9a0a8; }"));
  auto* buttons = new QHBoxLayout;
  for (QPushButton* b : {createButton_, startButton_, fullButton_, pauseButton_, resumeButton_,
                         heldButton_, terminateButton_}) {
    buttons->addWidget(b);
  }
  buttons->addStretch();
  buttons->addWidget(stopButton_);

  // ---- 发布列表和目标设备 ----
  releases_ = makeTable({QStringLiteral("发布号"), QStringLiteral("固件"), QStringLiteral("状态"),
                         QStringLiteral("金丝雀"), QStringLiteral("成功 / 失败 / 进行中 / 待确认 / 共"),
                         QStringLiteral("同时推送"), QStringLiteral("创建人"), QStringLiteral("创建时间"),
                         QStringLiteral("说明")},
                        this);
  targets_ = makeTable({QStringLiteral("设备"), QStringLiteral("批次"), QStringLiteral("状态"),
                        QStringLiteral("进度"), QStringLiteral("说明"), QStringLiteral("更新时间")},
                       this);
  targets_->setSelectionMode(QAbstractItemView::NoSelection);
  targetsTitle_ = new QLabel(this);
  auto* lower = new QWidget(this);
  auto* lowerLayout = new QVBoxLayout(lower);
  lowerLayout->setContentsMargins(0, 0, 0, 0);
  lowerLayout->addWidget(targetsTitle_);
  lowerLayout->addWidget(targets_);
  auto* splitter = new QSplitter(Qt::Vertical, this);
  splitter->addWidget(releases_);
  splitter->addWidget(lower);
  splitter->setStretchFactor(0, 2);
  splitter->setStretchFactor(1, 3);

  auto* hint = new QLabel(
      QStringLiteral("流程：新建发布 → 开始灰度（只推金丝雀）→ 金丝雀全部成功后观察 %1 秒 → 待确认全量 → "
                     "确认全量（每次最多同时推 K 台）。出现失败或安全告警自动暂停；离线设备记为“待确认”，"
                     "上线后由操作员确认再推。")
          .arg(rollout_->params().observeMs / 1000),
      this);
  hint->setWordWrap(true);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(buttons);
  layout->addWidget(hint);
  layout->addWidget(splitter);

  connect(createButton_, &QPushButton::clicked, this, &ReleasePage::createRelease);
  connect(startButton_, &QPushButton::clicked, this, [this]() {
    confirmAndRun(QStringLiteral("开始灰度"),
                  QStringLiteral("向发布 #%1 的金丝雀设备推送固件。").arg(selectedId()),
                  &AdminService::startCanary);
  });
  connect(fullButton_, &QPushButton::clicked, this, [this]() {
    confirmAndRun(QStringLiteral("确认全量"),
                  QStringLiteral("金丝雀已通过观察。向发布 #%1 的其余全部设备推送固件。").arg(selectedId()),
                  &AdminService::confirmFull);
  });
  connect(resumeButton_, &QPushButton::clicked, this, [this]() {
    confirmAndRun(QStringLiteral("继续"),
                  QStringLiteral("继续推送发布 #%1。请先确认暂停的原因已经排除。").arg(selectedId()),
                  &AdminService::resumeRelease);
  });
  connect(heldButton_, &QPushButton::clicked, this, [this]() {
    confirmAndRun(QStringLiteral("推送待确认设备"),
                  QStringLiteral("向发布 #%1 中“待确认”的设备推送固件（仍不在线的设备继续待确认）。")
                      .arg(selectedId()),
                  &AdminService::pushHeldDevices);
  });
  connect(terminateButton_, &QPushButton::clicked, this, [this]() {
    confirmAndRun(QStringLiteral("终止发布"),
                  QStringLiteral("终止发布 #%1。还没推送的设备不再推送，发布不能再继续。").arg(selectedId()),
                  &AdminService::terminateRelease);
  });
  connect(pauseButton_, &QPushButton::clicked, this, [this]() {
    runDirect(QStringLiteral("暂停"),
              QStringLiteral("暂停发布 #%1？正在升级的设备照常完成，之后不再推新的设备。").arg(selectedId()),
              &AdminService::pauseRelease);
  });
  connect(stopButton_, &QPushButton::clicked, this, [this]() {
    runDirect(QStringLiteral("紧急停止"),
              QStringLiteral("紧急停止发布 #%1？\n正在升级的设备会收到取消指令：还没开始写入的放弃升级并保留旧固件，"
                             "已在写入的完成或回滚。发布将终止，不能再继续。")
                  .arg(selectedId()),
              &AdminService::emergencyStop);
  });
  connect(releases_, &QTableWidget::itemSelectionChanged, this, [this]() {
    refreshTargets();
    updateButtons();
  });
  // 每条进度都会发 changed。合并成最多每 kRefreshCoalesceMs 重填一次（BUG-009）；
  // 本页按钮触发的操作仍然立刻 refresh()
  refreshTimer_ = new QTimer(this);
  refreshTimer_->setSingleShot(true);
  refreshTimer_->setInterval(kRefreshCoalesceMs);
  connect(refreshTimer_, &QTimer::timeout, this, &ReleasePage::refresh);
  connect(rollout_, &RolloutManager::changed, this, [this]() {
    if (!refreshTimer_->isActive()) refreshTimer_->start();
  });
  // 设备上下线会改变“推送待确认设备”是否有意义，顺带刷新一下按钮
  connect(registry_, &DeviceRegistry::deviceChanged, this, &ReleasePage::updateButtons);
  refresh();
  applyPermissions();
}

void ReleasePage::applyPermissions() {
  // 第一道权限检查：没有权限的按钮不出现。第二道在 AdminService 里
  const bool manage = admin_->can(Permission::ManageRelease);
  for (QPushButton* b : {createButton_, startButton_, fullButton_, pauseButton_, resumeButton_,
                         heldButton_, terminateButton_}) {
    b->setVisible(manage);
  }
  stopButton_->setVisible(admin_->can(Permission::EmergencyStop));
  updateButtons();
}

qint64 ReleasePage::selectedId() const {
  const int row = releases_->currentRow();
  if (row < 0 || !releases_->item(row, RelId)) return 0;
  return releases_->item(row, RelId)->data(Qt::UserRole).toLongLong();
}

QString ReleasePage::selectedState() const {
  const int row = releases_->currentRow();
  if (row < 0 || !releases_->item(row, RelState)) return QString();
  return releases_->item(row, RelState)->data(Qt::UserRole).toString();
}

void ReleasePage::updateButtons() {
  // 按钮可点 = 状态机里这一步走得通（设计 4.2 节状态图）。真正的裁决仍在业务层
  const QString s = selectedState();
  const bool pushing = s == QLatin1String("canary") || s == QLatin1String("full");
  startButton_->setEnabled(s == QLatin1String("draft"));
  fullButton_->setEnabled(s == QLatin1String("awaiting_full"));
  pauseButton_->setEnabled(pushing || s == QLatin1String("observing") ||
                           s == QLatin1String("awaiting_full"));
  resumeButton_->setEnabled(s == QLatin1String("paused"));
  heldButton_->setEnabled(pushing);
  terminateButton_->setEnabled(s == QLatin1String("draft") || s == QLatin1String("paused"));
  stopButton_->setEnabled(pushing || s == QLatin1String("observing") ||
                          s == QLatin1String("awaiting_full"));
}

void ReleasePage::refresh() {
  const qint64 keep = selectedId();
  const QList<ReleaseInfo> list = rollout_->releases(kReleaseRows);
  releases_->setRowCount(static_cast<int>(list.size()));
  int selectRow = list.isEmpty() ? -1 : 0;
  for (int row = 0; row < list.size(); ++row) {
    const ReleaseInfo& r = list.at(row);
    const QString canary =
        r.canaryGroup.isEmpty() ? QStringLiteral("%1 台（手动选择）").arg(r.canary)
                                : QStringLiteral("%1 台（分组 %2）").arg(r.canary).arg(r.canaryGroup);
    const QStringList cells = {
        QStringLiteral("#%1").arg(r.releaseId),
        QStringLiteral("%1 %2").arg(r.model, r.version),
        releaseStateText(r.state),
        canary,
        QStringLiteral("%1 / %2 / %3 / %4 / %5")
            .arg(r.success)
            .arg(r.failed)
            .arg(r.notified)
            .arg(r.held)
            .arg(r.total),
        QString::number(r.concurrency),
        r.createdBy,
        localTime(r.createdAt),
        r.note};
    for (int col = 0; col < RelCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (col == RelState) {
        item->setData(Qt::UserRole, r.state);
        const QColor color = stateColor(r.state);
        if (color.isValid()) item->setForeground(color);
      }
      releases_->setItem(row, col, item);
    }
    releases_->item(row, RelId)->setData(Qt::UserRole, r.releaseId);
    if (r.releaseId == keep) selectRow = row;
  }
  if (selectRow >= 0) releases_->selectRow(selectRow);
  fitColumns(releases_);
  refreshTargets();
  updateButtons();
}

void ReleasePage::refreshTargets() {
  const qint64 id = selectedId();
  const QList<TargetInfo> list = id > 0 ? rollout_->targets(id) : QList<TargetInfo>();
  targetsTitle_->setText(id > 0 ? QStringLiteral("发布 #%1 的目标设备（金丝雀在前）").arg(id)
                                : QStringLiteral("选中一个发布查看它的目标设备"));
  targets_->setRowCount(static_cast<int>(list.size()));
  for (int row = 0; row < list.size(); ++row) {
    const TargetInfo& t = list.at(row);
    const QStringList cells = {
        t.deviceId,
        t.phase == QLatin1String("canary") ? QStringLiteral("金丝雀") : QStringLiteral("全量"),
        targetStatusText(t.status),
        QStringLiteral("%1%").arg(t.progress),
        t.lastError,
        localTime(t.updatedAt)};
    for (int col = 0; col < TgtCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (col == TgtStatus) {
        const QColor color = stateColor(t.status);
        if (color.isValid()) item->setForeground(color);
      }
      targets_->setItem(row, col, item);
    }
  }
  fitColumns(targets_);
}

void ReleasePage::confirmAndRun(const QString& title, const QString& text,
                                bool (AdminService::*call)(qint64, const SecureBuffer&, QString*)) {
  const qint64 id = selectedId();
  if (id <= 0) return;
  SecureBuffer password;
  if (!askConfirmPassword(this, title, text, &password)) return;
  QString error;
  if (!(admin_->*call)(id, password, &error)) {
    QMessageBox::warning(this, title, QStringLiteral("没有执行。\n原因：%1").arg(error));
  }
  refresh();
}

void ReleasePage::runDirect(const QString& title, const QString& question,
                            bool (AdminService::*call)(qint64, QString*)) {
  const qint64 id = selectedId();
  if (id <= 0) return;
  if (QMessageBox::question(this, title, question) != QMessageBox::Yes) return;
  QString error;
  if (!(admin_->*call)(id, &error)) {
    QMessageBox::warning(this, title, QStringLiteral("没有执行。\n原因：%1").arg(error));
  }
  refresh();
}

void ReleasePage::createRelease() {
  QDialog dialog(this);
  dialog.setWindowTitle(QStringLiteral("新建发布"));
  dialog.setMinimumWidth(520);

  // 固件：只列启动检查通过的包
  auto* firmwareBox = new QComboBox(&dialog);
  for (const StoredPackage& p : firmware_->packages()) {
    if (!p.usable) continue;
    firmwareBox->addItem(QStringLiteral("%1 %2（安全版本号 %3）")
                             .arg(p.manifest.deviceModel, p.manifest.version)
                             .arg(p.manifest.securityVersion),
                         p.manifest.pkgId);
  }
  if (firmwareBox->count() == 0) {
    QMessageBox::information(this, dialog.windowTitle(), QStringLiteral("固件库里没有可用的固件包。"));
    return;
  }
  auto* groupBox = new QComboBox(&dialog);
  auto* deviceList = new QListWidget(&dialog);
  auto* concurrency = new QSpinBox(&dialog);
  concurrency->setRange(1, 100);
  concurrency->setValue(rollout_->params().concurrency);
  auto* summary = new QLabel(&dialog);
  summary->setWordWrap(true);

  // 选了固件之后：列出同型号、未停用的设备供勾选金丝雀，并列出它们的分组
  auto fillDevices = [&]() {
    StoredPackage p;
    firmware_->find(firmwareBox->currentData().toString(), &p);
    deviceList->clear();
    groupBox->clear();
    groupBox->addItem(QStringLiteral("（手动勾选）"), QString());
    QSet<QString> groups;
    for (const DeviceRecord& d : registry_->devices()) {
      if (d.disabled || d.model != p.manifest.deviceModel) continue;
      auto* item = new QListWidgetItem(
          QStringLiteral("%1　分组 %2　当前 %3　%4")
              .arg(d.deviceId, d.groupTag.isEmpty() ? QStringLiteral("—") : d.groupTag,
                   d.currentVersion.isEmpty() ? QStringLiteral("无固件") : d.currentVersion,
                   d.online ? QStringLiteral("在线") : QStringLiteral("离线")),
          deviceList);
      item->setData(Qt::UserRole, d.deviceId);
      item->setData(Qt::UserRole + 1, d.groupTag);
      item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
      item->setCheckState(Qt::Unchecked);
      if (!d.groupTag.isEmpty()) groups.insert(d.groupTag);
    }
    QStringList sorted(groups.cbegin(), groups.cend());
    sorted.sort();
    for (const QString& g : sorted) groupBox->addItem(QStringLiteral("分组 %1").arg(g), g);
  };
  // 选了分组：勾上这个分组的全部设备，其余取消
  auto applyGroup = [&]() {
    const QString group = groupBox->currentData().toString();
    if (group.isEmpty()) return;
    for (int i = 0; i < deviceList->count(); ++i) {
      QListWidgetItem* item = deviceList->item(i);
      item->setCheckState(item->data(Qt::UserRole + 1).toString() == group ? Qt::Checked
                                                                           : Qt::Unchecked);
    }
  };
  auto checkedDevices = [&]() {
    QStringList ids;
    for (int i = 0; i < deviceList->count(); ++i) {
      if (deviceList->item(i)->checkState() == Qt::Checked) {
        ids.append(deviceList->item(i)->data(Qt::UserRole).toString());
      }
    }
    return ids;
  };
  auto updateSummary = [&]() {
    const int canary = static_cast<int>(checkedDevices().size());
    summary->setText(QStringLiteral("金丝雀 %1 台。同型号的其余设备（已经是这个版本的除外）进入全量批，"
                                    "金丝雀通过后由操作员确认再推。")
                         .arg(canary));
  };
  connect(firmwareBox, &QComboBox::currentIndexChanged, &dialog, [&]() {
    fillDevices();
    updateSummary();
  });
  connect(groupBox, &QComboBox::currentIndexChanged, &dialog, [&]() {
    applyGroup();
    updateSummary();
  });
  connect(deviceList, &QListWidget::itemChanged, &dialog, [&]() { updateSummary(); });
  fillDevices();
  updateSummary();

  auto* form = new QFormLayout;
  form->addRow(QStringLiteral("固件"), firmwareBox);
  form->addRow(QStringLiteral("金丝雀"), groupBox);
  form->addRow(QString(), deviceList);
  form->addRow(QStringLiteral("同时推送台数"), concurrency);
  auto* box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  box->button(QDialogButtonBox::Ok)->setText(QStringLiteral("建为草稿"));
  box->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
  auto* layout = new QVBoxLayout(&dialog);
  layout->addLayout(form);
  layout->addWidget(summary);
  layout->addWidget(box);
  connect(box, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(box, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  if (dialog.exec() != QDialog::Accepted) return;

  // 勾选的正好是所选分组的全部设备时记下分组名，否则算手动勾选
  const QStringList canary = checkedDevices();
  QString group = groupBox->currentData().toString();
  if (!group.isEmpty()) {
    for (int i = 0; i < deviceList->count(); ++i) {
      const QListWidgetItem* item = deviceList->item(i);
      const bool inGroup = item->data(Qt::UserRole + 1).toString() == group;
      if (inGroup != (item->checkState() == Qt::Checked)) {
        group.clear();
        break;
      }
    }
  }
  qint64 releaseId = 0;
  QString error;
  if (!admin_->createRelease(firmwareBox->currentData().toString(), canary, group,
                             concurrency->value(), &releaseId, &error)) {
    QMessageBox::warning(this, dialog.windowTitle(), QStringLiteral("没有新建。\n原因：%1").arg(error));
    return;
  }
  refresh();
  // 选中新建的发布，方便接着点“开始灰度”
  for (int row = 0; row < releases_->rowCount(); ++row) {
    if (releases_->item(row, RelId)->data(Qt::UserRole).toLongLong() == releaseId) {
      releases_->selectRow(row);
      break;
    }
  }
}

}  // namespace fwds
