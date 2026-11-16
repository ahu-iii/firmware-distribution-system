// 客户端主窗口（骨架）：显示设备 ID、服务端地址、连接状态、最后一次心跳应答和本地事件。
// A/B 分区、升级进度、演示面板在后续步骤加入。
#pragma once

#include <QMainWindow>

#include "client/net/tcp_client.h"

class QLabel;
class QPlainTextEdit;

namespace fwds {

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  MainWindow(const ClientConfig& config, TcpClient* client, QWidget* parent = nullptr);

 private:
  void appendLog(const QString& line);

  QLabel* stateLabel_;
  QLabel* ackLabel_;
  QPlainTextEdit* log_;
};

}  // namespace fwds
