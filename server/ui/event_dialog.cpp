#include "server/ui/event_dialog.h"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace fwds {

namespace {

constexpr int kShownEvents = 200;  // 最多显示最近多少条

QString kindText(const QString& kind) {
  if (kind == QLatin1String("progress")) return QStringLiteral("进度");
  if (kind == QLatin1String("result")) return QStringLiteral("结果");
  if (kind == QLatin1String("alert")) return QStringLiteral("告警");
  return kind;
}

// 一条事件的要点，给人看的一行字
QString describe(const StoredEvent& e) {
  const QJsonObject& p = e.payload;
  const int code = p.value(QStringLiteral("code")).toInt();
  if (e.kind == QLatin1String("progress")) {
    return QStringLiteral("%1 %2%").arg(p.value(QStringLiteral("state")).toString())
        .arg(p.value(QStringLiteral("progress")).toInt());
  }
  if (e.kind == QLatin1String("result")) {
    return QStringLiteral("%1，错误码 %2，运行版本 %3")
        .arg(p.value(QStringLiteral("result")).toString())
        .arg(code)
        .arg(p.value(QStringLiteral("fw_version")).toString());
  }
  return QStringLiteral("错误码 %1：%2").arg(code).arg(p.value(QStringLiteral("detail")).toString());
}

QString localTime(const QDateTime& t) {
  return t.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
}

}  // namespace

EventDialog::EventDialog(EventStore* events, const QString& deviceId, QWidget* parent)
    : QDialog(parent), events_(events), deviceId_(deviceId) {
  setWindowTitle(QStringLiteral("设备事件 - %1").arg(deviceId));
  resize(820, 480);

  summary_ = new QLabel(this);
  table_ = new QTableWidget(0, 5, this);
  table_->setHorizontalHeaderLabels({QStringLiteral("序号"), QStringLiteral("设备时间"),
                                     QStringLiteral("类型"), QStringLiteral("内容"),
                                     QStringLiteral("入库时间")});
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->verticalHeader()->setVisible(false);
  table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
  auto* refresh = buttons->addButton(QStringLiteral("刷新"), QDialogButtonBox::ActionRole);
  connect(refresh, &QPushButton::clicked, this, &EventDialog::reload);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

  auto* layout = new QVBoxLayout(this);
  layout->addWidget(summary_);
  layout->addWidget(table_);
  layout->addWidget(buttons);
  reload();
}

void EventDialog::reload() {
  const qint64 ack = events_->eventAck(deviceId_);
  const int held = events_->heldCount(deviceId_);
  // 对账结论：序号 1 ~ ack 连续收齐；held 不为 0 表示后面还有事件在等 ack + 1
  summary_->setText(held == 0
                        ? QStringLiteral("已连续收到序号 1 ~ %1，没有暂存的事件").arg(ack)
                        : QStringLiteral("已连续收到序号 1 ~ %1；暂存 %2 条，等待设备补传序号 %3")
                              .arg(ack)
                              .arg(held)
                              .arg(ack + 1));

  const QList<StoredEvent> list = events_->recentEvents(deviceId_, kShownEvents);
  table_->setRowCount(list.size());
  for (int row = 0; row < list.size(); ++row) {
    const StoredEvent& e = list.at(row);
    const QStringList cells = {QString::number(e.seq), localTime(e.ts), kindText(e.kind),
                               describe(e), localTime(e.receivedAt)};
    for (int col = 0; col < cells.size(); ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (e.seq > ack) item->setForeground(Qt::gray);  // 暂存的事件灰色显示
      table_->setItem(row, col, item);
    }
  }
}

}  // namespace fwds
