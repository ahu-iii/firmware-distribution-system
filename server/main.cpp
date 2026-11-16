// fwds-server：分发服务端入口。
// 用法：fwds-server --config <配置文件> [--headless]
#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <memory>

#include "common/config.h"
#include "common/log.h"
#include "common/net/channel_security.h"
#include "server/business/login_handler.h"
#include "server/net/tcp_server.h"
#include "server/ui/main_window.h"

#ifdef FWDS_DEV_PLAINTEXT
#include "common/net/plaintext_dev_channel.h"
#endif

// 信道安全实现。TLS 层（TlsContext / CertVerifier）在开发 1 的下一步接入；
// 在那之前，非开发构建返回空指针，程序不启动网络，避免以明文对外提供服务。
static std::unique_ptr<fwds::ChannelSecurity> makeChannelSecurity() {
#ifdef FWDS_DEV_PLAINTEXT
  qCWarning(fwds::lcSecurity) << "DEV BUILD: plaintext channel in use, not for delivery";
  return std::make_unique<fwds::PlaintextDevChannel>();
#else
  return nullptr;
#endif
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

  const std::unique_ptr<fwds::ChannelSecurity> security = makeChannelSecurity();
  if (!security) {
    qCCritical(fwds::lcApp) << "TLS layer not implemented yet; configure with the 'dev' preset to "
                               "use the plaintext development channel";
    return 3;
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
