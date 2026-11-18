#include "server/ui/log_page.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTimeEdit>
#include <QDir>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include "server/storage/run_log_reader.h"

namespace fwds {

namespace {

enum Column { ColTime, ColLevel, ColModule, ColText, ColCount };

constexpr int kMaxRows = 1000;  // 一次最多显示的条数

// 日志里的模块名（Qt 日志分类）和界面上显示的名字
const QList<QPair<QString, QString>>& modules() {
  static const QList<QPair<QString, QString>> kModules = {
      {QStringLiteral("fwds.net"), QStringLiteral("网络（连接、登录、心跳）")},
      {QStringLiteral("fwds.security"), QStringLiteral("安全（证书、非法帧、告警）")},
      {QStringLiteral("fwds.app"), QStringLiteral("程序（下发、发布、固件库）")},
      {QStringLiteral("fwds.audit"), QStringLiteral("管理操作")},
      {QStringLiteral("default"), QStringLiteral("其他（Qt 自身）")}};
  return kModules;
}

}  // namespace

LogPage::LogPage(DeviceRegistry* registry, const LogFileParams& logFile, const QString& name,
                 QWidget* parent)
    : QWidget(parent), registry_(registry), logFile_(logFile), name_(name) {
  device_ = new QComboBox(this);
  level_ = new QComboBox(this);
  level_->addItem(QStringLiteral("全部级别"), QString());
  for (const char* l : {"SECURITY", "ERROR", "WARN", "INFO", "DEBUG"}) {
    level_->addItem(QString::fromLatin1(l), QString::fromLatin1(l));
  }
  module_ = new QComboBox(this);
  module_->addItem(QStringLiteral("全部模块"), QString());
  for (const auto& m : modules()) module_->addItem(m.second, m.first);

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
  keyword_->setPlaceholderText(QStringLiteral("关键字，例如 3007、timeout、回滚"));
  keyword_->setClearButtonEnabled(true);
  auto* searchButton = new QPushButton(QStringLiteral("查询"), this);

  auto* top = new QHBoxLayout;
  top->addWidget(new QLabel(QStringLiteral("设备"), this));
  top->addWidget(device_);
  top->addWidget(level_);
  top->addWidget(module_);
  top->addWidget(useTime_);
  top->addWidget(from_);
  top->addWidget(new QLabel(QStringLiteral("至"), this));
  top->addWidget(to_);
  top->addWidget(keyword_, 1);
  top->addWidget(searchButton);

  table_ = new QTableWidget(0, ColCount, this);
  table_->setHorizontalHeaderLabels(
      {QStringLiteral("时间"), QStringLiteral("级别"), QStringLiteral("模块"), QStringLiteral("内容")});
  table_->horizontalHeader()->setSectionResizeMode(ColText, QHeaderView::Stretch);
  table_->verticalHeader()->setVisible(false);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setWordWrap(false);

  status_ = new QLabel(this);
  status_->setTextInteractionFlags(Qt::TextSelectableByMouse);

  auto* layout = new QVBoxLayout(this);
  layout->addLayout(top);
  layout->addWidget(table_);
  layout->addWidget(status_);

  connect(useTime_, &QCheckBox::toggled, from_, &QWidget::setEnabled);
  connect(useTime_, &QCheckBox::toggled, to_, &QWidget::setEnabled);
  connect(searchButton, &QPushButton::clicked, this, &LogPage::search);
  connect(keyword_, &QLineEdit::returnPressed, this, &LogPage::search);
  reloadDevices();
}

void LogPage::refresh() {
  reloadDevices();
  search();
}

void LogPage::reloadDevices() {
  const QString current = device_->currentData().toString();
  device_->clear();
  device_->addItem(QStringLiteral("全部设备"), QString());
  for (const DeviceRecord& d : registry_->devices()) device_->addItem(d.deviceId, d.deviceId);
  const int index = device_->findData(current);
  device_->setCurrentIndex(index < 0 ? 0 : index);
}

void LogPage::search() {
  RunLogFilter filter;
  filter.deviceId = device_->currentData().toString();
  filter.level = level_->currentData().toString();
  filter.module = module_->currentData().toString();
  filter.keyword = keyword_->text().trimmed();
  if (useTime_->isChecked()) {
    filter.from = from_->dateTime().toUTC();
    filter.to = to_->dateTime().toUTC();
  }
  filter.limit = kMaxRows;
  const QStringList files = logFilePaths(logFile_, name_);
  const RunLogResult result = searchRunLog(files, filter);

  table_->setRowCount(0);
  table_->setRowCount(result.lines.size());
  for (int row = 0; row < result.lines.size(); ++row) {
    const RunLogLine& line = result.lines.at(row);
    const QStringList cells = {line.ts.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")),
                               line.level, line.module, line.text};
    // WARN、ERROR、SECURITY、FATAL 标红，一眼能看到出问题的地方
    const bool bad = line.level != QLatin1String("INFO") && line.level != QLatin1String("DEBUG");
    for (int col = 0; col < ColCount; ++col) {
      auto* item = new QTableWidgetItem(cells.at(col));
      if (col == ColText) item->setToolTip(line.text);
      if (bad) item->setForeground(QColor(0xb0, 0x00, 0x20));
      table_->setItem(row, col, item);
    }
  }
  table_->resizeColumnsToContents();
  table_->horizontalHeader()->setSectionResizeMode(ColText, QHeaderView::Stretch);

  QString text = QStringLiteral("找到 %1 条").arg(result.lines.size());
  if (result.truncated) text += QStringLiteral("（只显示最新的 %1 条，请加条件缩小范围）").arg(kMaxRows);
  text += QStringLiteral("，共读取 %1 行，%2 个日志文件，目录 %3")
              .arg(result.scannedLines)
              .arg(files.size())
              .arg(QDir::toNativeSeparators(QDir(logFile_.dir).absolutePath()));
  status_->setText(text);
}

}  // namespace fwds
