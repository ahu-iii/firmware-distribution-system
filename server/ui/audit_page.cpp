#include "server/ui/audit_page.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
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
  auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
  auto* verifyButton = new QPushButton(QStringLiteral("校验日志完整性"), this);
  auto* top = new QHBoxLayout;
  top->addWidget(category_);
  top->addWidget(refreshButton);
  top->addWidget(verifyButton);
  top->addStretch();

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

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(top);
  layout->addWidget(chainLabel_);
  layout->addWidget(resultLabel_);
  layout->addWidget(table_);

  connect(refreshButton, &QPushButton::clicked, this, &AuditPage::refresh);
  connect(category_, &QComboBox::currentIndexChanged, this, &AuditPage::refresh);
  connect(verifyButton, &QPushButton::clicked, this, &AuditPage::verify);
}

void AuditPage::refresh() {
  chainLabel_->setText(QStringLiteral("哈希链最新：第 %1 条　%2")
                           .arg(audit_->lastId())
                           .arg(audit_->lastHash()));
  QList<AuditEntry> entries;
  QString error;
  if (!admin_->recentAudit(kAuditRows, category_->currentData().toString(), &entries, &error)) {
    table_->setRowCount(0);
    resultLabel_->setText(error);
    return;
  }
  table_->setRowCount(static_cast<int>(entries.size()));
  for (int row = 0; row < entries.size(); ++row) {
    const AuditEntry& e = entries.at(row);
    const QStringList cells = {
        QString::number(e.id),
        e.ts.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
        e.level, e.category, e.actor, e.source, e.deviceId, e.message};
    for (int col = 0; col < ColCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (e.level == QLatin1String("WARN")) item->setForeground(QColor(0xb0, 0x00, 0x20));
      table_->setItem(row, col, item);
    }
  }
}

void AuditPage::verify() {
  AuditCheck check;
  QString error;
  if (!admin_->verifyAudit(&check, &error)) {
    resultLabel_->setText(error);
    return;
  }
  resultLabel_->setText((check.ok ? QStringLiteral("✔ ") : QStringLiteral("✘ ")) + check.detail);
  resultLabel_->setStyleSheet(check.ok ? QStringLiteral("color: #1b7f3b; font-weight: bold;")
                                       : QStringLiteral("color: #b00020; font-weight: bold;"));
  refresh();
  // 定位到第一条对不上的记录
  if (check.firstBadId > 0) {
    for (int row = 0; row < table_->rowCount(); ++row) {
      if (table_->item(row, ColId)->text().toLongLong() == check.firstBadId) {
        table_->selectRow(row);
        table_->scrollToItem(table_->item(row, ColId));
        break;
      }
    }
  }
}

}  // namespace fwds
