#include "server/ui/audit_page.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTimeEdit>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace fwds {

namespace {

enum Column { ColId, ColTime, ColLevel, ColCategory, ColActor, ColSource, ColDevice, ColMessage, ColCount };

constexpr int kAuditRows = 500;  // 最多显示的条数

}  // namespace

AuditPage::AuditPage(AuditService* audit, AdminService* admin, QWidget* parent)
    : QWidget(parent), audit_(audit), admin_(admin) {
  category_ = new QComboBox(this);
  category_->addItem(QStringLiteral("全部分类"), QString());
  for (const QString& c : {audit::kRollout, audit::kAdmin, audit::kAuth, audit::kUpgrade,
                           audit::kSecurity, audit::kConn, audit::kHeartbeat}) {
    category_->addItem(c, c);
  }
  // 设备 ID 直接输入：审计日志里也有未登记设备的记录（如证书被拒），不能只从已登记设备里选
  device_ = new QLineEdit(this);
  device_->setPlaceholderText(QStringLiteral("设备 ID，例如 DEV-001"));
  device_->setClearButtonEnabled(true);
  // 时间段用本机时间输入，检索时换成 UTC 和日志里的时间比较
  useTime_ = new QCheckBox(QStringLiteral("时间"), this);
  from_ = new QDateTimeEdit(QDateTime::currentDateTime().addSecs(-3600), this);
  to_ = new QDateTimeEdit(QDateTime::currentDateTime().addSecs(3600), this);
  for (QDateTimeEdit* edit : {from_, to_}) {
    edit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    edit->setCalendarPopup(true);
    edit->setEnabled(false);
  }
  keyword_ = new QLineEdit(this);
  keyword_->setPlaceholderText(QStringLiteral("关键字，例如 dispatch、ROLLED_BACK、操作员账号"));
  keyword_->setClearButtonEnabled(true);
  auto* searchButton = new QPushButton(QStringLiteral("查询"), this);
  auto* verifyButton = new QPushButton(QStringLiteral("校验日志完整性"), this);

  auto* top = new QHBoxLayout;
  top->addWidget(category_);
  top->addWidget(new QLabel(QStringLiteral("设备"), this));
  top->addWidget(device_);
  top->addWidget(useTime_);
  top->addWidget(from_);
  top->addWidget(new QLabel(QStringLiteral("至"), this));
  top->addWidget(to_);
  top->addWidget(keyword_, 1);
  top->addWidget(searchButton);
  top->addWidget(verifyButton);

  chainLabel_ = new QLabel(this);
  chainLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);  // 方便抄录、复制
  resultLabel_ = new QLabel(this);
  resultLabel_->setWordWrap(true);

  table_ = new QTableWidget(0, ColCount, this);
  table_->setHorizontalHeaderLabels({QStringLiteral("序号"), QStringLiteral("时间"),
                                     QStringLiteral("级别"), QStringLiteral("分类"),
                                     QStringLiteral("操作者"), QStringLiteral("来源"),
                                     QStringLiteral("设备"), QStringLiteral("内容")});
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->verticalHeader()->setVisible(false);
  table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setStretchLastSection(true);

  status_ = new QLabel(this);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(top);
  layout->addWidget(chainLabel_);
  layout->addWidget(resultLabel_);
  layout->addWidget(table_);
  layout->addWidget(status_);

  connect(useTime_, &QCheckBox::toggled, from_, &QWidget::setEnabled);
  connect(useTime_, &QCheckBox::toggled, to_, &QWidget::setEnabled);
  connect(searchButton, &QPushButton::clicked, this, &AuditPage::refresh);
  connect(device_, &QLineEdit::returnPressed, this, &AuditPage::refresh);
  connect(keyword_, &QLineEdit::returnPressed, this, &AuditPage::refresh);
  connect(category_, &QComboBox::currentIndexChanged, this, &AuditPage::refresh);
  connect(verifyButton, &QPushButton::clicked, this, &AuditPage::verify);
}

void AuditPage::refresh() {
  chainLabel_->setText(QStringLiteral("哈希链最新：第 %1 条　%2")
                           .arg(audit_->lastId())
                           .arg(audit_->lastHash()));
  AuditFilter filter;
  filter.category = category_->currentData().toString();
  filter.deviceId = device_->text().trimmed();
  filter.keyword = keyword_->text().trimmed();
  if (useTime_->isChecked()) {
    filter.from = from_->dateTime().toUTC();
    filter.to = to_->dateTime().toUTC();
  }
  filter.limit = kAuditRows;

  AuditSearchResult result;
  QString error;
  if (!admin_->searchAudit(filter, &result, &error)) {
    table_->setRowCount(0);
    status_->clear();
    resultLabel_->setText(error);
    return;
  }
  const QList<AuditEntry>& entries = result.entries;
  table_->setRowCount(static_cast<int>(entries.size()));
  for (int row = 0; row < entries.size(); ++row) {
    const AuditEntry& e = entries.at(row);
    const QStringList cells = {
        QString::number(e.id),
        e.ts.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
        e.level, e.category, e.actor, e.source, e.deviceId, e.message};
    for (int col = 0; col < ColCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (col == ColMessage) item->setToolTip(e.message);
      if (e.level == QLatin1String("WARN")) item->setForeground(QColor(0xb0, 0x00, 0x20));
      table_->setItem(row, col, item);
    }
  }
  QString text = QStringLiteral("找到 %1 条").arg(entries.size());
  if (result.truncated) {
    text += QStringLiteral("（只显示最新的 %1 条，请加条件缩小范围）").arg(kAuditRows);
  }
  status_->setText(text);
}

void AuditPage::verify() {
  AuditCheck check;
  QString error;
  if (!admin_->verifyAudit(&check, &error)) {
    resultLabel_->setText(error);
    return;
  }
  QString text = (check.ok ? QStringLiteral("✔ ") : QStringLiteral("✘ ")) + check.detail;
  refresh();
  // 定位到第一条对不上的记录。校验的是整张表，这条记录可能被当前检索条件筛掉了
  if (check.firstBadId > 0 && !selectEntry(check.firstBadId)) {
    text += QStringLiteral("（第 %1 条不在当前检索结果里，清空检索条件后可以看到）").arg(check.firstBadId);
  }
  resultLabel_->setText(text);
  resultLabel_->setStyleSheet(check.ok ? QStringLiteral("color: #1b7f3b; font-weight: bold;")
                                       : QStringLiteral("color: #b00020; font-weight: bold;"));
}

bool AuditPage::selectEntry(qint64 id) {
  for (int row = 0; row < table_->rowCount(); ++row) {
    if (table_->item(row, ColId)->text().toLongLong() == id) {
      table_->selectRow(row);
      table_->scrollToItem(table_->item(row, ColId));
      return true;
    }
  }
  return false;
}

}  // namespace fwds
