#include "client/ui/demo_panel.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QPushButton>

#include "client/business/demo_actions.h"

namespace fwds {

namespace {

constexpr int kCutAtPercent = 50;  // “写入时断电”在写入进度到多少时触发

}  // namespace

DemoPanel::DemoPanel(const QString& dataDir, TcpClient* client, Updater* updater, QWidget* parent)
    : QGroupBox(QStringLiteral("演示面板"), parent), dataDir_(dataDir), client_(client), updater_(updater) {
  networkButton_ = new QPushButton(QStringLiteral("模拟断网"), this);
  networkButton_->setCheckable(true);
  networkButton_->setToolTip(QStringLiteral("断开当前连接并停止重连，像网线被拔掉；再点一次恢复"));
  cutDuringWrite_ = new QCheckBox(QStringLiteral("写入到 %1% 时断电").arg(kCutAtPercent), this);
  cutDuringWrite_->setToolTip(QStringLiteral("勾选后，下一次升级写入分区进度到 %1% 时程序当场结束").arg(kCutAtPercent));
  auto* powerButton = new QPushButton(QStringLiteral("立即断电"), this);
  powerButton->setToolTip(QStringLiteral("程序当场结束：不发 BYE、不做任何收尾，只留下已刷到磁盘的数据"));
  powerButton->setStyleSheet(QStringLiteral("color: #b00020;"));
  auto* tamperButton = new QPushButton(QStringLiteral("篡改下载缓存"), this);
  tamperButton->setToolTip(QStringLiteral("把正在下载（或断点暂停）的镜像缓存改掉一个字节"));

  auto* layout = new QHBoxLayout(this);
  layout->addWidget(networkButton_);
  layout->addWidget(cutDuringWrite_);
  layout->addWidget(powerButton);
  layout->addWidget(tamperButton);
  layout->addStretch();

  connect(networkButton_, &QPushButton::toggled, this, &DemoPanel::onNetworkToggled);
  connect(powerButton, &QPushButton::clicked, this, []() { simulatePowerLoss(); });
  connect(tamperButton, &QPushButton::clicked, this, &DemoPanel::onTamper);
  connect(updater_, &Updater::progressChanged, this, &DemoPanel::onProgress);
}

void DemoPanel::onNetworkToggled(bool blocked) {
  networkButton_->setText(blocked ? QStringLiteral("恢复网络") : QStringLiteral("模拟断网"));
  client_->setNetworkBlocked(blocked);
  emit actionLogged(blocked ? QStringLiteral("演示：模拟断网") : QStringLiteral("演示：恢复网络"));
}

void DemoPanel::onTamper() {
  QString detail;
  tamperDownloadCache(dataDir_, &detail);
  emit actionLogged(QStringLiteral("演示：篡改下载缓存，%1").arg(detail));
}

void DemoPanel::onProgress(int percent) {
  if (!cutDuringWrite_->isChecked()) return;
  if (updater_->state() != Updater::State::Writing || percent < kCutAtPercent) return;
  simulatePowerLoss();  // 不返回
}

}  // namespace fwds
