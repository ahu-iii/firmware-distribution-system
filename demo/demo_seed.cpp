// fwds-demo-seed：答辩演示用的数据准备工具，只在 demo/setup.sh 里调用，不随安装包发布。
//
// 演示前要在服务端做的准备（建账号、注册设备、导入固件）原本都要在界面上点，
// 现场点错一步就会卡住。这个工具把这些步骤一次做完，走的是界面背后同一个 AdminService：
// 同样的角色检查、证书校验、整包验签，每一步同样写进审计哈希链，结果和在界面上操作完全一样。
//
// 用法：
//   fwds-demo-seed --config <服务端配置>
//                  --maintainer <用户名> --operator <用户名> --auditor <用户名>
//                  --device <证书.pem>,<型号>,<分组> ...（可重复）
//                  --firmware <固件包.fwpkg> ...（可重复）
// 演示账号的口令从环境变量 FWDS_DEMO_ACCOUNT_PASSWORD 读取（读后清除），三个账号用同一个口令。
// 只接受空数据库：账号表里已有账号就拒绝执行，不会改动已在使用的服务端数据。
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFile>
#include <QTextStream>

#include "common/config.h"
#include "common/crypto/rand.h"
#include "common/crypto/secure_buffer.h"
#include "common/log.h"
#include "common/security/cert_verifier.h"
#include "common/security/fsk_public_key.h"
#include "common/security/key_store.h"
#include "server/business/admin_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/firmware_repo.h"
#include "server/security/audit_service.h"
#include "server/security/operator_auth.h"
#include "server/storage/database.h"

namespace {

constexpr char kAccountPasswordEnv[] = "FWDS_DEMO_ACCOUNT_PASSWORD";

int fail(const QString& message) {
  QTextStream(stderr) << "fwds-demo-seed: " << message << "\n";
  return 1;
}

bool readAll(const QString& path, QByteArray* content) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) return false;
  *content = file.readAll();
  return true;
}

// 新建账号第一次登录必须改口令（设计 11.4 节）。这里先用一个随机的初始口令建账号，
// 再以该账号登录、把口令改成演示口令，演示时直接用演示口令登录即可。
// 随机初始口令只在内存里，用完即清除。
bool createAndActivate(fwds::AdminService* admin, const QString& maintainer,
                       const fwds::SecureBuffer& password, const QString& username, fwds::Role role,
                       QString* error) {
  const QByteArray random = "Init" + fwds::randomBytes(12).toHex();  // 含字母和数字，满足口令规则
  const fwds::SecureBuffer initial = fwds::SecureBuffer::fromBytes(random.constData(), random.size());
  QString message;
  if (admin->login(maintainer, password, &message) != fwds::AuthResult::Ok) {
    *error = message;
    return false;
  }
  if (!admin->createAccount(username, role, initial, error)) return false;
  if (admin->login(username, initial, &message) != fwds::AuthResult::Ok) {
    *error = message;
    return false;
  }
  if (!admin->changeOwnPassword(initial, password, error)) return false;
  admin->logout();
  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  QCoreApplication app(argc, argv);
  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("答辩演示数据准备：建账号、注册设备、导入固件"));
  parser.addHelpOption();
  const QCommandLineOption configOpt(QStringLiteral("config"), QStringLiteral("服务端配置文件"),
                                     QStringLiteral("file"));
  const QCommandLineOption maintainerOpt(QStringLiteral("maintainer"), QStringLiteral("维护员用户名"),
                                         QStringLiteral("name"));
  const QCommandLineOption operatorOpt(QStringLiteral("operator"), QStringLiteral("操作员用户名"),
                                       QStringLiteral("name"));
  const QCommandLineOption auditorOpt(QStringLiteral("auditor"), QStringLiteral("审计员用户名"),
                                      QStringLiteral("name"));
  const QCommandLineOption deviceOpt(QStringLiteral("device"),
                                     QStringLiteral("设备证书,型号,分组（可重复）"),
                                     QStringLiteral("pem,model,group"));
  const QCommandLineOption firmwareOpt(QStringLiteral("firmware"),
                                       QStringLiteral("要导入的固件包（可重复）"),
                                       QStringLiteral("fwpkg"));
  for (const QCommandLineOption& option :
       {configOpt, maintainerOpt, operatorOpt, auditorOpt, deviceOpt, firmwareOpt}) {
    parser.addOption(option);
  }
  parser.process(app);
  for (const QCommandLineOption& option : {configOpt, maintainerOpt, operatorOpt, auditorOpt}) {
    if (!parser.isSet(option)) return fail(QStringLiteral("缺少 --%1").arg(option.names().first()));
  }

  fwds::initLogging(QStringLiteral("WARN"));
  fwds::ServerConfig config;
  QString error;
  if (!fwds::loadServerConfig(parser.value(configOpt), &config, &error)) return fail(error);

  fwds::SecureBuffer password;
  if (!fwds::takePassphraseFromEnv(kAccountPasswordEnv, &password)) {
    return fail(QStringLiteral("没有设置环境变量 %1（演示账号口令）")
                    .arg(QString::fromLatin1(kAccountPasswordEnv)));
  }

  // 和 fwds-server 的 main 一样组装：FSK 公钥（核对指纹）、CA 与 CRL、数据库、审计、各模块
  fwds::ManifestVerifier fskVerifier;
  if (!fwds::loadPinnedFskPublicKey(config.fskPubFile, config.fskPubSha256, &fskVerifier, &error)) {
    return fail(error);
  }
  fwds::CertVerifier certVerifier(fwds::CertLimits{config.tls.maxCaCertDays, config.tls.maxCertDays});
  QByteArray caPem;
  QByteArray crlPem;
  if (!readAll(config.tls.caFile, &caPem) || !readAll(config.tls.crlFile, &crlPem)) {
    return fail(QStringLiteral("读不到 CA 证书或 CRL"));
  }
  if (!certVerifier.loadCa(caPem, &error) || !certVerifier.loadCrl(crlPem, &error)) return fail(error);

  fwds::Database database;
  if (!database.open(config.dbFile, &error)) return fail(error);
  fwds::AuditService audit(&database, config.auditCheckpointFile);
  if (!audit.load(&error)) return fail(error);
  fwds::DeviceRegistry registry(&database);
  if (!registry.load(&error)) return fail(error);
  fwds::OperatorAuth auth(&database);
  fwds::DispatchGate gate;
  fwds::AdminService admin(&auth, &registry, &gate);
  admin.setCertVerifier(&certVerifier);
  admin.setAuditService(&audit);
  fwds::FirmwareRepo firmware(&database, fskVerifier, config.firmwareDir);
  if (!firmware.load(&error)) return fail(error);
  admin.setFirmwareRepo(&firmware);

  QTextStream out(stdout);
  // ① 账号：第一个维护员走首次运行的初始化，其余账号由维护员创建
  const QString maintainer = parser.value(maintainerOpt);
  if (!admin.needsBootstrap()) return fail(QStringLiteral("数据库里已经有账号，只能对新数据库执行"));
  if (!admin.bootstrapMaintainer(maintainer, password, &error)) return fail(error);
  if (!createAndActivate(&admin, maintainer, password, parser.value(operatorOpt), fwds::Role::Operator,
                         &error) ||
      !createAndActivate(&admin, maintainer, password, parser.value(auditorOpt), fwds::Role::Auditor,
                         &error)) {
    return fail(error);
  }
  out << "账号：维护员 " << maintainer << "，操作员 " << parser.value(operatorOpt) << "，审计员 "
      << parser.value(auditorOpt) << "\n";

  // ② 设备和固件都是维护员的操作
  QString message;
  if (admin.login(maintainer, password, &message) != fwds::AuthResult::Ok) return fail(message);
  for (const QString& spec : parser.values(deviceOpt)) {
    const QStringList parts = spec.split(QLatin1Char(','));
    QByteArray certPem;
    if (parts.size() != 3 || !readAll(parts[0], &certPem)) {
      return fail(QStringLiteral("--device 格式应为 证书.pem,型号,分组：%1").arg(spec));
    }
    if (!admin.registerDevice(certPem, parts[1], parts[2], &error)) return fail(error);
    out << "注册设备：" << parts[0] << "（" << parts[1] << "，分组 " << parts[2] << "）\n";
  }
  for (const QString& path : parser.values(firmwareOpt)) {
    if (!admin.importFirmware(path, &error)) return fail(error);
    out << "导入固件：" << path << "\n";
  }
  admin.logout();
  out << "完成，审计日志 " << (audit.verify().ok ? "哈希链完整" : "校验不通过") << "\n";
  return 0;
}
