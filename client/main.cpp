// fwds-client：设备客户端入口。多开时每个实例用自己的配置文件模拟一台设备。
// 用法：fwds-client --config <配置文件> [--headless]
// 启动前须设置环境变量 FWDS_KEY_PASSPHRASE（设备私钥口令），程序读取后立即清除。
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
#include "common/security/key_store.h"
#include "common/security/tls_channel.h"

// 建立 TLS 信道：私钥口令从环境变量取（取走即清除），证书和私钥文件的位置来自配置。
// 任何一项缺失或不合格都返回空指针，程序不发起连接——没有“不加密也能跑”的路径。
static std::unique_ptr<fwds::TlsChannelSecurity> makeChannelSecurity(
    const fwds::ClientConfig& config, QString* error) {
  fwds::SecureBuffer passphrase;
  if (!fwds::takePassphraseFromEnv(fwds::kKeyPassphraseEnv, &passphrase)) {
    *error = QStringLiteral("没有设置环境变量 %1（设备私钥口令）")
                 .arg(QString::fromLatin1(fwds::kKeyPassphraseEnv));
    return nullptr;
  }
  auto security = std::make_unique<fwds::TlsChannelSecurity>(
      fwds::CertLimits{config.tls.maxCaCertDays, config.tls.maxCertDays});
  if (!security->loadFiles(config.tls, passphrase, error)) return nullptr;
  // 服务端证书的名称必须等于这里配置的主机名或 IP
  security->setExpectedServerName(config.serverHost);
  // 设备证书是给哪台设备签的，就只能由哪台设备用
  if (security->localIdentity().name != config.deviceId) {
    *error = QStringLiteral("设备证书名称 %1 与配置的 device_id %2 不一致")
                 .arg(security->localIdentity().name, config.deviceId);
    return nullptr;
  }
  return security;
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

  const std::unique_ptr<fwds::TlsChannelSecurity> security = makeChannelSecurity(config, &error);
  if (!security) {
    qCCritical(fwds::lcApp).noquote() << "TLS setup failed:" << error;
    return 3;
  }
  if (QDateTime::currentDateTimeUtc().daysTo(security->localCertNotAfter()) < 15) {
    qCWarning(fwds::lcSecurity) << "device certificate expires within 15 days, issue a new one";
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
