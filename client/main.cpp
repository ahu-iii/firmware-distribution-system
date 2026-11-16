// fwds-client：设备客户端入口。多开时每个实例用自己的配置文件模拟一台设备。
// 用法：fwds-client --config <配置文件> [--headless]
#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <memory>

#include "client/net/tcp_client.h"
#include "client/ui/main_window.h"
#include "common/config.h"
#include "common/log.h"
#include "common/net/channel_security.h"

#ifdef FWDS_DEV_PLAINTEXT
#include "common/net/plaintext_dev_channel.h"
#endif

// 信道安全实现。TLS 层（TlsContext / CertVerifier）在开发 1 的下一步接入；
// 在那之前，非开发构建返回空指针，程序不发起连接，避免明文上线。
static std::unique_ptr<fwds::ChannelSecurity> makeChannelSecurity() {
#ifdef FWDS_DEV_PLAINTEXT
  qCWarning(fwds::lcSecurity) << "DEV BUILD: plaintext channel in use, not for delivery";
  return std::make_unique<fwds::PlaintextDevChannel>();
#else
  return nullptr;
#endif
}

int main(int argc, char* argv[]) {
  bool headless = false;
  for (int i = 1; i < argc; ++i) {
    if (qstrcmp(argv[i], "--headless") == 0) headless = true;
  }
  std::unique_ptr<QCoreApplication> app;
  if (headless) app = std::make_unique<QCoreApplication>(argc, argv);
  else app = std::make_unique<QApplication>(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("fwds-client"));
  QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("工业固件安全升级分发系统 - 设备客户端"));
  parser.addHelpOption();
  parser.addVersionOption();
  const QCommandLineOption configOpt(QStringLiteral("config"), QStringLiteral("配置文件路径（必填）"),
                                     QStringLiteral("file"));
  const QCommandLineOption headlessOpt(QStringLiteral("headless"), QStringLiteral("不显示界面"));
  parser.addOption(configOpt);
  parser.addOption(headlessOpt);
  parser.process(*app);

  fwds::initLogging(QStringLiteral("INFO"));
  fwds::ClientConfig config;
  QString error;
  if (!fwds::loadClientConfig(parser.value(configOpt), &config, &error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 2;
  }
  fwds::initLogging(config.logLevel);

  const std::unique_ptr<fwds::ChannelSecurity> security = makeChannelSecurity();
  if (!security) {
    qCCritical(fwds::lcApp) << "TLS layer not implemented yet; configure with the 'dev' preset to "
                               "use the plaintext development channel";
    return 3;
  }

  fwds::TcpClient client(config, security.get());
  QElapsedTimer uptime;
  uptime.start();

  // LOGIN 和 HEARTBEAT 的内容以后由 Updater / Bootloader 提供真实的版本、分区和升级状态；
  // 目前只填网络层联调需要的字段。
  client.setLoginProvider([&config]() {
    QJsonObject login;
    login.insert(QStringLiteral("device_id"), config.deviceId);
    login.insert(QStringLiteral("model"), config.model);
    login.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
    return login;
  });
  client.setHeartbeatProvider([&uptime]() {
    QJsonObject hb;
    hb.insert(QStringLiteral("state"), QStringLiteral("IDLE"));
    hb.insert(QStringLiteral("progress"), 0);
    hb.insert(QStringLiteral("uptime"), uptime.elapsed() / 1000);
    return hb;
  });

  std::unique_ptr<fwds::MainWindow> window;
  if (!headless) {
    window = std::make_unique<fwds::MainWindow>(config, &client);
    window->show();
  }
  QObject::connect(app.get(), &QCoreApplication::aboutToQuit, &client, [&client]() { client.stop(); });
  client.start();
  return app->exec();
}
