// DemoPanel：客户端主窗口里的“演示面板”（设计第 6 节），答辩时用来制造故障场景：
//   模拟断网 / 恢复网络  演示断点续传（FT-06）、离线运行界面不卡（FT-07）、事件补传（FT-08）
//   写入到 50% 时断电    勾选后，升级写入分区进度到 50% 时进程当场结束（FT-14），重启后仍从原分区启动
//   立即断电            任何时候当场结束进程，例如在 REBOOTING 时断电演示上电补完升级或回滚
//   篡改下载缓存        改掉 .part 的一个字节，演示续传前重验、写入前整镜像再验（ST-20）
// 自检失败回滚（FT-13）不需要面板：下发一份用 make-image --selftest-fail 做的固件即可。
// 面板只调用网络层和 demo_actions 的接口，界面里不直接读写文件。
#pragma once

#include <QGroupBox>

#include "client/business/updater.h"
#include "client/net/tcp_client.h"

class QCheckBox;
class QPushButton;

namespace fwds {

class DemoPanel : public QGroupBox {
  Q_OBJECT
 public:
  DemoPanel(const QString& dataDir, TcpClient* client, Updater* updater, QWidget* parent = nullptr);

 signals:
  // 每个演示动作做了什么，主窗口写进本地日志。
  void actionLogged(const QString& text);

 private:
  void onNetworkToggled(bool blocked);
  void onTamper();
  void onProgress(int percent);

  QString dataDir_;
  TcpClient* client_;
  Updater* updater_;
  QPushButton* networkButton_;
  QCheckBox* cutDuringWrite_;
};

}  // namespace fwds
