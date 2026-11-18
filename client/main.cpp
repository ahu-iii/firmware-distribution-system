// fwds-client：设备客户端入口。多开时每个实例用自己的配置文件模拟一台设备。
// 用法：fwds-client --config <配置文件> [--headless]
//       fwds-client --config <配置文件> --provision <固件包.fwpkg>   出厂写入第一份固件后退出
// 启动前须设置环境变量 FWDS_KEY_PASSPHRASE（设备私钥口令），程序读取后立即清除。
// 启动顺序：读配置 → 装入固件签名公钥（核对指纹）→ 建立 TLS 材料 → Bootloader 选分区 → 连接服务端。
#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <memory>

#include "client/business/event_outbox.h"
#include "client/business/event_reporter.h"
#include "client/business/provisioner.h"
#include "client/business/updater.h"
#include "client/net/tcp_client.h"
#include "common/security/fsk_public_key.h"
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
  const QCommandLineOption provisionOpt(
      QStringLiteral("provision"),
      QStringLiteral("出厂写入：把这个 .fwpkg 装进空设备的分区 a，然后退出"), QStringLiteral("fwpkg"));
  parser.addOption(configOpt);
  parser.addOption(headlessOpt);
  parser.addOption(provisionOpt);
  parser.process(*app);

  fwds::initLogging(QStringLiteral("INFO"));
  fwds::ClientConfig config;
  QString error;
  if (!fwds::loadClientConfig(parser.value(configOpt), &config, &error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 2;
  }
  fwds::initLogging(config.logLevel);

  // 固件签名公钥：设备只装这把公钥对应的私钥签过的固件。指纹对不上就不运行
  fwds::ManifestVerifier fskVerifier;
  if (!fwds::loadPinnedFskPublicKey(config.fskPubFile, config.fskPubSha256, &fskVerifier, &error)) {
    qCCritical(fwds::lcSecurity).noquote() << error;
    return 4;
  }

  // 出厂写入模式：不联网，装好第一份固件就退出
  if (parser.isSet(provisionOpt)) {
    if (!fwds::provisionDevice(config.dataDir, parser.value(provisionOpt), fskVerifier, config.model,
                               &error)) {
      qCCritical(fwds::lcApp).noquote() << "provision failed:" << error;
      return 5;
    }
    qCInfo(fwds::lcApp).noquote() << "factory firmware installed in" << config.dataDir;
    return 0;
  }

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

  // 升级状态机。它要发的帧（CHUNK_REQ 等）交给网络层；网络层收到的业务帧和连接状态交给它
  fwds::Updater updater(config, fskVerifier, [&client](fwds::MsgType type, const QByteArray& body) {
    return client.send(type, body);
  });
  QObject::connect(&client, &fwds::TcpClient::frameReceived, &updater, &fwds::Updater::handleFrame);
  QObject::connect(&client, &fwds::TcpClient::stateChanged, &updater,
                   [&updater](fwds::TcpClient::State state) {
                     updater.setOnline(state == fwds::TcpClient::State::Online);
                   });
  // 模拟重启：先说 BYE 断开连接，Bootloader 跑完后重新连接、重新登录（带上新的版本号）
  QObject::connect(&updater, &fwds::Updater::rebootRequested, &client,
                   [&client]() { client.stop(QStringLiteral("reboot")); });
  QObject::connect(&updater, &fwds::Updater::rebootFinished, &client, [&client]() { client.start(); });
  QObject::connect(&updater, &fwds::Updater::finished, &updater,
                   [](const QString& result, int code, const QString& detail) {
                     qCInfo(fwds::lcApp).noquote() << "update result:" << result << code << detail;
                   });

  // 事件闭环（设计 4.6 节）：升级的进度、结果、告警先写进 outbox 并刷盘，再发给服务端；
  // 服务端在 LOGIN_RESULT 和 HEARTBEAT_ACK 里确认到哪个序号，outbox 就删到哪个序号；
  // 断线期间只落盘不发送，重新登录后按序号补传
  fwds::EventOutbox outbox(QDir(config.dataDir).filePath(QStringLiteral("outbox")),
                           [&client](fwds::MsgType type, const QByteArray& body) {
                             return client.send(type, body);
                           });
  if (!outbox.open(&error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 6;
  }
  fwds::EventReporter reporter(&updater, &outbox);
  QObject::connect(&client, &fwds::TcpClient::loggedIn, &outbox, [&outbox](const QJsonObject& result) {
    outbox.onLoggedIn(result.value(QStringLiteral("event_ack")).toInteger());
  });
  QObject::connect(&client, &fwds::TcpClient::heartbeatAcked, &outbox, [&outbox](const QJsonObject& ack) {
    outbox.onAcked(ack.value(QStringLiteral("event_ack")).toInteger(-1));
  });
  QObject::connect(&client, &fwds::TcpClient::stateChanged, &outbox,
                   [&outbox](fwds::TcpClient::State state) {
                     if (state != fwds::TcpClient::State::Online) outbox.onDisconnected();
                   });

  // LOGIN 带上当前运行的固件版本、安全版本号和活动分区；HEARTBEAT 带上升级状态和进度
  // LOGIN 还带上 event_base：本地已确认并删除的最大事件序号，服务端拿它和自己的记录对账
  client.setLoginProvider([&config, &updater, &outbox]() {
    QJsonObject login = updater.loginFields();
    login.insert(QStringLiteral("device_id"), config.deviceId);
    login.insert(QStringLiteral("model"), config.model);
    login.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
    login.insert(QStringLiteral("event_base"), outbox.confirmedSeq());
    return login;
  });
  client.setHeartbeatProvider([&uptime, &updater]() {
    QJsonObject hb;
    hb.insert(QStringLiteral("state"), updater.stateName());
    hb.insert(QStringLiteral("progress"), updater.progress());
    hb.insert(QStringLiteral("uptime"), uptime.elapsed() / 1000);
    return hb;
  });

  std::unique_ptr<fwds::MainWindow> window;
  if (!headless) {
    window = std::make_unique<fwds::MainWindow>(config, &client, &updater, &outbox);
    window->show();
  }
  QObject::connect(app.get(), &QCoreApplication::aboutToQuit, &client, [&client]() { client.stop(); });

  // 上电：Bootloader 验签并选定运行的分区，然后才联网
  updater.powerOn();
  if (!updater.bootState().hasFirmware) {
    qCCritical(fwds::lcApp) << "no bootable firmware, recovery mode: waiting for the server to push one";
  }
  client.start();
  return app->exec();
}
