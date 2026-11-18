// 客户端主窗口：显示设备 ID、服务端地址、连接状态、最后一次心跳应答、
// 当前固件和 A/B 分区、升级状态与进度、待上报事件、本地日志。演示面板在后续步骤加入。
// 界面只读取 Updater、EventOutbox 的状态、订阅它们的信号，不直接碰文件和网络。
// 服务端断开时界面照常响应：网络层和升级模块都是事件驱动的，没有阻塞等待。
#pragma once

#include <QMainWindow>

#include "client/business/event_outbox.h"
#include "client/business/updater.h"
#include "client/net/tcp_client.h"

class QLabel;
class QPlainTextEdit;
class QProgressBar;

namespace fwds {

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  MainWindow(const ClientConfig& config, TcpClient* client, Updater* updater, EventOutbox* outbox,
             QWidget* parent = nullptr);

 private:
  void appendLog(const QString& line);
  void showFirmware();  // 刷新“当前固件”“分区”两行
  void showOutbox();    // 刷新“待上报事件”一行

  Updater* updater_;
  EventOutbox* outbox_;
  QLabel* outboxLabel_;
  QLabel* firmwareLabel_;
  QLabel* slotLabel_;
  QLabel* updateLabel_;
  QProgressBar* progressBar_;

  QLabel* stateLabel_;
  QLabel* ackLabel_;
  QPlainTextEdit* log_;
};

}  // namespace fwds
