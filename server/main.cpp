// fwds-server：分发服务端入口。
// 用法：fwds-server --config <配置文件> [--headless]
//       fwds-server --config <配置文件> --check   部署自检：检查各项材料、迁移并检查数据库，然后退出
// 启动前须设置环境变量 FWDS_KEY_PASSPHRASE（服务端私钥口令），程序读取后立即清除。
// 启动顺序：读配置 → 装入固件签名公钥（核对指纹）→ 程序自校验 → 建立 TLS 材料 → 数据库 → 各模块 → 监听。
#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QSqlQuery>
#include <QTextStream>
#include <QTimer>
#include <memory>

#include "common/build_info.h"
#include "common/config.h"
#include "common/log.h"
#include "common/shutdown_signal.h"
#include "common/protocol.h"
#include "common/security/exe_signature.h"
#include "common/security/fsk_public_key.h"
#include "common/security/key_store.h"
#include "common/security/tls_channel.h"
#include "server/business/admin_service.h"
#include "server/business/chunk_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/license_verifier.h"
#include "server/business/login_handler.h"
#include "server/business/login_throttle.h"
#include "server/business/rollout_manager.h"
#include "server/net/tcp_server.h"
#include "server/security/audit_service.h"
#include "server/security/operator_auth.h"
#include "server/storage/database.h"
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

// 数一张表有多少行，读不出来返回 -1。
static qint64 countRows(fwds::Database& db, const QString& table) {
  QSqlQuery query(db.handle());
  if (!query.exec(QStringLiteral("SELECT COUNT(*) FROM \"%1\"").arg(table)) || !query.next()) return -1;
  return query.value(0).toLongLong();
}

// --check 的输出：每行“名称=值”，部署脚本在升级前后各取一次比对（设计 8.4 节冒烟检查）。
// 审计哈希链校验不通过返回 false。
static bool printCheckSummary(fwds::Database& db, const fwds::AuditService& audit) {
  QTextStream out(stdout);
  out << "version=" << fwds::kAppVersion << "\n";
  out << "schema_version=" << db.schemaVersion() << "\n";
  out << "devices=" << countRows(db, QStringLiteral("device")) << "\n";
  out << "firmware=" << countRows(db, QStringLiteral("firmware")) << "\n";
  out << "releases=" << countRows(db, QStringLiteral("release")) << "\n";
  out << "audit_rows=" << countRows(db, QStringLiteral("audit_log")) << "\n";
  const fwds::AuditCheck chain = audit.verify();
  out << "audit_chain=" << (chain.ok ? QStringLiteral("ok") : QStringLiteral("bad")) << "\n";
  if (!chain.ok) out << "audit_detail=" << chain.detail << "\n";
  return chain.ok;
}

int main(int argc, char* argv[]) {
  // 作为后台服务运行时没有图形环境，--headless 下不创建界面
  // --check、--version、--help 同样不需要界面（部署脚本在没有图形环境的机器上也要调用）
  bool headless = false;
  for (int i = 1; i < argc; ++i) {
    if (qstrcmp(argv[i], "--headless") == 0 || qstrcmp(argv[i], "--check") == 0 ||
        qstrcmp(argv[i], "--version") == 0 || qstrcmp(argv[i], "--help") == 0) {
      headless = true;
    }
  }
  std::unique_ptr<QCoreApplication> app;
  if (headless) app = std::make_unique<QCoreApplication>(argc, argv);
  else app = std::make_unique<QApplication>(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("fwds-server"));
  QCoreApplication::setApplicationVersion(QString::fromLatin1(fwds::kAppVersion));

  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("工业固件安全升级分发系统 - 服务端"));
  parser.addHelpOption();
  parser.addVersionOption();
  const QCommandLineOption configOpt(QStringLiteral("config"), QStringLiteral("配置文件路径（必填）"),
                                     QStringLiteral("file"));
  const QCommandLineOption headlessOpt(QStringLiteral("headless"), QStringLiteral("不显示界面"));
  const QCommandLineOption checkOpt(
      QStringLiteral("check"),
      QStringLiteral("部署自检：检查配置、公钥、程序签名、证书和私钥，迁移并检查数据库，输出统计后退出"));
  parser.addOption(configOpt);
  parser.addOption(headlessOpt);
  parser.addOption(checkOpt);
  parser.process(*app);

  fwds::initLogging(QStringLiteral("INFO"));
  fwds::ServerConfig config;
  QString error;
  if (!fwds::loadServerConfig(parser.value(configOpt), &config, &error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 2;
  }
  fwds::initLogging(config.logLevel);

  qCInfo(fwds::lcApp).noquote() << "fwds-server" << fwds::kAppVersion << "schema"
                                << fwds::kSchemaVersion << "protocol" << int(fwds::kProtocolVersion);

  // 固件签名公钥：服务端只让这把公钥验得过的固件包进固件库，许可证和程序签名也用它验。
  // 指纹和配置对不上就不启动
  fwds::ManifestVerifier fskVerifier;
  if (!fwds::loadPinnedFskPublicKey(config.fskPubFile, config.fskPubSha256, &fskVerifier, &error)) {
    qCCritical(fwds::lcSecurity).noquote() << error;
    return 5;
  }
  // 程序自校验（设计第 15 节）：程序文件被改过就不运行
  if (!fwds::selfCheckExecutable(fskVerifier, &error)) {
    qCCritical(fwds::lcSecurity).noquote() << error;
    return 7;
  }

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


  // 存储层：数据库（设备注册表、账号表、固件表、发布表）。旧结构在这里迁移到当前版本
  fwds::Database database;
  if (!database.open(config.dbFile, &error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 4;
  }

  // 审计日志：接着数据库里已有的哈希链往后写
  fwds::AuditService auditService(&database, config.auditCheckpointFile);
  if (!auditService.load(&error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 4;
  }
  // 部署自检到此为止：不加载设备表和发布表（加载时会改写在线状态、暂停进行中的发布）
  if (parser.isSet(checkOpt)) return printCheckSummary(database, auditService) ? 0 : 8;

  fwds::DeviceRegistry registry(&database);
  if (!registry.load(&error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 4;
  }

  // 安全层与业务层：账号、“允许下发”开关（每次启动默认关闭）、管理操作入口
  fwds::OperatorAuth operatorAuth(&database);
  fwds::DispatchGate dispatchGate;
  fwds::AdminService admin(&operatorAuth, &registry, &dispatchGate);
  admin.setCertVerifier(&security->verifier());
  admin.setAuditService(&auditService);

  // 网络层 + 登录裁决 + 在线状态同步
  fwds::TcpServer server(config, security.get());
  fwds::LoginThrottle loginThrottle(config.loginFailLimit, config.loginFailWindowS * 1000LL,
                                    config.loginLockS * 1000LL);
  // 许可证：LOGIN 带来的 device.lic 用 FSK 公钥验签，核对设备 ID 和有效期，不过返回 2006
  fwds::FskLicenseVerifier licenseVerifier(&fskVerifier);
  fwds::LoginHandler loginHandler(config.protocol, &registry, &loginThrottle, &licenseVerifier);
  fwds::HeartbeatMonitor heartbeatMonitor(&server, &registry);
  // 事件入库与对账：设备上报的进度、结果、告警按 (设备, 序号) 去重入库，登录时按 event_base 对账
  fwds::EventStore eventStore(&database, &registry, &server);
  loginHandler.setEventStore(&eventStore);
  // 固件库：启动时把库里的每个包重新检查一遍（验签、逐片哈希、整镜像哈希）
  fwds::FirmwareRepo firmwareRepo(&database, fskVerifier, config.firmwareDir);
  if (!firmwareRepo.load(&error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 4;
  }
  // 分片服务应答设备的 CHUNK_REQ；给哪台设备下发哪个包由发布模块裁决（开关、互锁）后交给它
  fwds::ChunkService chunkService(&server, config.protocol);
  // 灰度发布：发布状态机、互锁、并发控制（设计 4.2 节）
  fwds::RolloutManager rollout(&database, config.protocol, config.rollout, &registry, &firmwareRepo,
                               &chunkService, &dispatchGate);
  rollout.setAuditService(&auditService);
  if (!rollout.load(&error)) {
    qCCritical(fwds::lcApp).noquote() << error;
    return 4;
  }
  admin.setFirmwareRepo(&firmwareRepo);
  admin.setRolloutManager(&rollout);
  // 设备的升级结果、进度、告警先由 EventStore 去重、按序入库，再交给发布模块推进或暂停发布。
  // 只接入库成功的事件：重复补传的事件 EventStore 不会再发信号，发布不会被推进两次。
  QObject::connect(&eventStore, &fwds::EventStore::resultStored, &rollout,
                   &fwds::RolloutManager::onDeviceResult);
  QObject::connect(&eventStore, &fwds::EventStore::progressStored, &rollout,
                   &fwds::RolloutManager::onDeviceProgress);
  QObject::connect(&eventStore, &fwds::EventStore::alertStored, &rollout,
                   &fwds::RolloutManager::onDeviceAlert);
  QObject::connect(&server, &fwds::TcpServer::sessionOpened, &loginHandler,
                   [&loginHandler](fwds::Session* session) {
                     QObject::connect(session, &fwds::Session::loginRequested, &loginHandler,
                                      &fwds::LoginHandler::handle);
                   });
  if (!server.start()) return 1;

  // 界面：先显示锁定的主窗口，事件循环转起来之后弹登录对话框。
  // 无界面模式下没有人登录，只做监控，不能执行任何管理操作。
  std::unique_ptr<fwds::MainWindow> window;
  if (!headless) {
    window = std::make_unique<fwds::MainWindow>(&server, &registry, &admin, &dispatchGate,
                                                &firmwareRepo, &rollout, &auditService);
    window->setEventStore(&eventStore);
    window->show();
    QTimer::singleShot(0, window.get(), &fwds::MainWindow::promptLogin);
  }
  fwds::quitOnTerminationSignal(app.get());
  return app->exec();
}
