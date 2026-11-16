// 服务端主窗口（骨架）：目前只有连接列表，显示每条连接的地址、状态、设备 ID、最后心跳。
// 完整的设备监控、固件库、灰度发布、日志页面在后续步骤加入。
// UI 层只通过信号槽拿数据，不碰 socket。
#pragma once

#include <QHash>
#include <QMainWindow>

class QTableWidget;
class QLabel;

namespace fwds {

class Session;
class TcpServer;

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  explicit MainWindow(TcpServer* server, QWidget* parent = nullptr);

 private:
  void onSessionOpened(Session* session);
  void onSessionClosed(Session* session);
  void refreshRow(Session* session);
  int rowOf(quint64 sessionId) const;

  TcpServer* server_;
  QTableWidget* table_;
  QLabel* summary_;
};

}  // namespace fwds
