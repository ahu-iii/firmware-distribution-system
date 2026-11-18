// 设备监控页（设计第 6 节）：设备表的列宽按内容调整，但不在每条进度更新时重新量一遍。
// 回归 BUG-006：原来用 QHeaderView::ResizeToContents，几十台设备同时升级时每条 PROGRESS
// 都触发全表重新排版，服务端界面卡住数秒（测试报告 PT-02、PT-03）。
#include <QApplication>
#include <QElapsedTimer>
#include <QHeaderView>
#include <QTableView>
#include <gtest/gtest.h>

#include "server/ui/device_page.h"
#include "server/ui/device_table_model.h"
#include "tests/test_server_env.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

TEST(DevicePage, ProgressUpdatesRefitColumnsOnceInsteadOfEveryTime) {
  ServerBackend backend;
  backend.registerDevice(sharedPki().dev001);
  const QString dev = QStringLiteral("DEV-001");
  backend.registry.markOnline(dev, QStringLiteral("127.0.0.1"), QStringLiteral("2.0.0"), 4);

  DevicePage page(&backend.registry, &backend.admin);
  page.resize(1360, 600);
  page.show();
  QApplication::processEvents();
  auto* table = page.findChild<QTableView*>();
  ASSERT_NE(table, nullptr);
  const int col = DeviceTableModel::ColUpgradeState;
  EXPECT_EQ(table->horizontalHeader()->sectionResizeMode(col), QHeaderView::Interactive);
  const int before = table->columnWidth(col);

  // 一连串进度更新：升级状态换成一个很长的字符串。更新当时列宽不变（不逐条重新排版）
  const QString longState = QStringLiteral("DOWNLOADING-").repeated(8);
  for (int p = 0; p <= 100; ++p) backend.registry.markProgress(dev, longState, p);
  QApplication::processEvents();
  EXPECT_EQ(table->columnWidth(col), before);

  // 合并定时器到期后按内容调整一次，长字符串能完整显示
  EXPECT_TRUE(waitFor([&]() { return table->columnWidth(col) > before; },
                      DevicePage::kColumnFitIntervalMs + 2000));
  EXPECT_GT(table->columnWidth(col), table->fontMetrics().horizontalAdvance(longState));
}
