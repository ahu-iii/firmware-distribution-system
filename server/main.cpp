// fwds-server：分发服务端入口。
// 用法：fwds-server --config <配置文件> [--headless]
// 启动前须设置环境变量 FWDS_KEY_PASSPHRASE（服务端私钥口令），程序读取后立即清除。
#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <memory>

#include "common/config.h"
#include "common/log.h"
#include "common/security/key_store.h"
#include "common/security/tls_channel.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "server/ui/main_window.h"

// 建立 TLS 信道：私钥口令从环境变量取（取走即清除），证书和私钥文件的位置来自配置。
// 任何一项缺失或不合格都返回空指针，程序不启动网络——没有“不加密也能跑”的路径。
static std::unique_ptr<fwds::TlsChannelSecurity> makeChannelSecurity(const fwds::TlsConfig& tls,
                                                                     QString* error) {
  fwds::SecureBuffer passphrase;
  if (!fwds::takePassphraseFromEnv(fwds::kKeyPassphraseEnv, &passphrase)) {
    *error = QStringLiteral("没有设置环境变量 %1（服务端私钥口令）")
                 .arg(QString::fromLatin1(fwds::kKeyPassphraseEnv));
    return nullptr;
  }
  auto security = std::make_unique<fwds::TlsChannelSecurity>(
      fwds::CertLimits{tls.maxCaCertDays, tls.maxCertDays});
  if (!security->loadFiles(tls, passphrase, error)) return nullptr;
  return security;
}

int main(int argc, char* argv[]) {
  // 作为后台服务运行时没有图形环境，--headless 下不创建界面
  bool headless = false;
  for (int i = 1; i < argc; ++i) {
    if (qstrcmp(argv[i], "--headless") == 0) headless = true;
  }
  std::unique_ptr<QCoreApplication> app;
  if (headless) app = std::make_unique<QCoreApplication>(argc, argv);
  else app = std::make_unique<QApplication>(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("fwds-server"));
  QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("工业固件安全升级分发系统 - 服务端"));
  parser.addHelpOption();
  parser.addVersionOption();
  const QCommandLineOption configOpt(QStringLiteral("config"), QStringLiteral("配置文件路径（必填）"),
                                     QStringLiteral("file"));
  const QCommandLineOption headlessOpt(QStringLiteral("headless"), QStringLiteral("不显示界面"));
  parser.addOption(configOpt);
  parser.addOption(headlessOpt);
  parser.process(*app);

  fwds::initLogging(QStringLiteral("INFO"));
  fwds::ServerConfig config;
  QString error;
  if (!fwds::loadServerConfig(parser.value(configOpt), &config, &error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 2;
  }
  fwds::initLogging(config.logLevel);

  const std::unique_ptr<fwds::TlsChannelSecurity> security =
      makeChannelSecurity(config.tls, &error);
  if (!security) {
    qCCritical(fwds::lcApp).noquote() << "TLS setup failed:" << error;
    return 3;
  }
  qCInfo(fwds::lcApp).noquote() << "TLS ready, server certificate" << security->localIdentity().name
                                << "valid until"
                                << security->localCertNotAfter().toString(Qt::ISODate);
  // 证书轮换提醒（设计 11.4 节）：到期前 15 天开始告警
  if (QDateTime::currentDateTimeUtc().daysTo(security->localCertNotAfter()) < 15) {
    qCWarning(fwds::lcSecurity) << "server certificate expires within 15 days, issue a new one";
  }

  fwds::TcpServer server(config, security.get());
  fwds::LoginHandler loginHandler(config.protocol);
  QObject::connect(&server, &fwds::TcpServer::sessionOpened, &loginHandler,
                   [&loginHandler](fwds::Session* session) {
                     QObject::connect(session, &fwds::Session::loginRequested, &loginHandler,
                                      &fwds::LoginHandler::handle);
                   });
  if (!server.start()) return 1;

  std::unique_ptr<fwds::MainWindow> window;
  if (!headless) {
    window = std::make_unique<fwds::MainWindow>(&server);
    window->show();
  }
  return app->exec();
}
