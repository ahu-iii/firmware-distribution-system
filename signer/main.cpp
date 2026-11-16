// fwds-signer：离线签发工具（命令行），只在签发主机上运行。
// 证书相关的子命令（ca-init、issue-cert、revoke、update-crl、list-certs）已实现；
// 固件相关的（sign-fw、sign-exe、issue-lic）属于开发 2。
//
// 口令：CA 口令每次在终端输入（不回显）；没有终端时从环境变量 FWDS_CA_PASSPHRASE 读取。
// 新签发的服务端 / 设备私钥的口令同理，环境变量是 FWDS_KEY_PASSPHRASE。
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTextStream>
#include <memory>

#include "common/config.h"
#include "common/security/key_store.h"
#include "signer/ca_store.h"
#include "signer/passphrase_prompt.h"

namespace {

using fwds::CaStore;
using fwds::SecureBuffer;

struct Command {
  const char* name;
  const char* summary;
};

// 子命令清单，对应设计第 3 节。
const Command kCommands[] = {
    {"ca-init", "生成自建 CA 根密钥、根证书和空的 CRL"},
    {"issue-cert", "为服务端或设备签发证书"},
    {"revoke", "吊销证书并更新 CRL"},
    {"update-crl", "重新生成 CRL（吊销名单不变，刷新有效期）"},
    {"list-certs", "列出已签发的证书"},
    {"sign-fw", "对固件镜像生成 manifest、签名并打包为 .fwpkg"},
    {"sign-exe", "给客户端程序签名"},
    {"issue-lic", "签发设备许可证 device.lic"},
};

QTextStream& out() {
  static QTextStream stream(stdout);
  return stream;
}

QTextStream& err() {
  static QTextStream stream(stderr);
  return stream;
}

void printUsage(QTextStream& stream) {
  stream << "用法：fwds-signer <子命令> [选项]\n"
            "      fwds-signer <子命令> --help   查看该子命令的选项\n\n子命令：\n";
  for (const Command& c : kCommands) {
    stream << "  " << QString::fromLatin1(c.name).leftJustified(12) << QString::fromUtf8(c.summary)
           << "\n";
  }
}

int fail(const QString& message) {
  err() << "错误：" << message << "\n";
  return 1;
}

// 各子命令共用的选项。
struct CommonOptions {
  QCommandLineOption caDir{QStringLiteral("ca-dir"), QStringLiteral("CA 目录（必填）"),
                           QStringLiteral("dir")};
  QCommandLineOption config{QStringLiteral("config"),
                            QStringLiteral("配置文件，提供证书有效期上限和 CRL 有效天数（可选）"),
                            QStringLiteral("file")};
};

// 解析命令行并打开 CA 目录。出错时打印原因并返回 false。
bool openStore(QCommandLineParser& parser, const CommonOptions& common, const QStringList& args,
               std::unique_ptr<CaStore>* store) {
  parser.addHelpOption();
  parser.addOption(common.caDir);
  parser.addOption(common.config);
  parser.process(args);

  if (!parser.isSet(common.caDir)) {
    fail(QStringLiteral("缺少 --ca-dir"));
    return false;
  }
  fwds::SignerConfig config;
  QString error;
  if (parser.isSet(common.config) &&
      !fwds::loadSignerConfig(parser.value(common.config), &config, &error)) {
    fail(error);
    return false;
  }
  fwds::SignerPolicy policy;
  policy.caDays = config.maxCaCertDays;
  policy.leafDays = config.maxCertDays;
  policy.crlDays = config.crlValidDays;
  *store = std::make_unique<CaStore>(parser.value(common.caDir), policy);
  return true;
}

// 读 --days。没给返回 0（表示用上限）；不是正整数返回 -1。
int daysOption(const QCommandLineParser& parser, const QCommandLineOption& option) {
  if (!parser.isSet(option)) return 0;
  bool ok = false;
  const int days = parser.value(option).toInt(&ok);
  return ok && days > 0 ? days : -1;
}

bool askCaPassphrase(bool isNew, SecureBuffer* passphrase) {
  QString error;
  const QString prompt = isNew ? QStringLiteral("设置 CA 口令（至少 12 个字符）：")
                               : QStringLiteral("CA 口令：");
  if (fwds::obtainPassphrase(fwds::kCaPassphraseEnv, prompt, isNew, passphrase, &error)) return true;
  fail(error);
  return false;
}

int cmdCaInit(const QStringList& args) {
  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("生成自建 CA：ca.key（加密）、ca.pem、crl.pem、index.json"));
  const CommonOptions common;
  const QCommandLineOption nameOpt(QStringLiteral("name"), QStringLiteral("CA 名称"),
                                   QStringLiteral("name"), QStringLiteral("FWDS Root CA"));
  const QCommandLineOption daysOpt(QStringLiteral("days"),
                                   QStringLiteral("根证书有效天数，默认取配置的上限"),
                                   QStringLiteral("n"));
  parser.addOption(nameOpt);
  parser.addOption(daysOpt);
  std::unique_ptr<CaStore> store;
  if (!openStore(parser, common, args, &store)) return 1;
  const int days = daysOption(parser, daysOpt);
  if (days < 0) return fail(QStringLiteral("--days 必须是正整数"));

  SecureBuffer caPassphrase;
  if (!askCaPassphrase(true, &caPassphrase)) return 1;
  QString error;
  if (!store->init(parser.value(nameOpt), days, caPassphrase, &error)) return fail(error);

  out() << "CA 已建立。\n  根证书：" << store->caCertPath() << "\n  CRL：   " << store->crlPath()
        << "\n请把 CA 目录留在签发主机上，不要放进仓库。\n";
  return 0;
}

int cmdIssueCert(const QStringList& args) {
  QCommandLineParser parser;
  parser.setApplicationDescription(
      QStringLiteral("签发证书。输出目录里得到 <type>.pem、<type>.key（加密）、ca.pem、crl.pem"));
  const CommonOptions common;
  const QCommandLineOption typeOpt(QStringLiteral("type"), QStringLiteral("server 或 device（必填）"),
                                   QStringLiteral("type"));
  const QCommandLineOption nameOpt(
      QStringLiteral("name"),
      QStringLiteral("证书名称（必填）：服务端填客户端连接时用的主机名或 IP，设备填设备 ID"),
      QStringLiteral("name"));
  const QCommandLineOption outOpt(QStringLiteral("out-dir"), QStringLiteral("输出目录（必填）"),
                                  QStringLiteral("dir"));
  const QCommandLineOption daysOpt(QStringLiteral("days"),
                                   QStringLiteral("证书有效天数，默认取配置的上限"),
                                   QStringLiteral("n"));
  parser.addOption(typeOpt);
  parser.addOption(nameOpt);
  parser.addOption(outOpt);
  parser.addOption(daysOpt);
  std::unique_ptr<CaStore> store;
  if (!openStore(parser, common, args, &store)) return 1;

  const QString typeText = parser.value(typeOpt);
  if (typeText != QLatin1String("server") && typeText != QLatin1String("device")) {
    return fail(QStringLiteral("--type 必须是 server 或 device"));
  }
  const fwds::CertType type =
      typeText == QLatin1String("server") ? fwds::CertType::Server : fwds::CertType::Device;
  if (!parser.isSet(nameOpt) || !parser.isSet(outOpt)) {
    return fail(QStringLiteral("缺少 --name 或 --out-dir"));
  }
  const int days = daysOption(parser, daysOpt);
  if (days < 0) return fail(QStringLiteral("--days 必须是正整数"));

  SecureBuffer caPassphrase;
  SecureBuffer keyPassphrase;
  QString error;
  if (!askCaPassphrase(false, &caPassphrase)) return 1;
  if (!fwds::obtainPassphrase(fwds::kKeyPassphraseEnv,
                              QStringLiteral("为新私钥设置口令（至少 12 个字符）："), true,
                              &keyPassphrase, &error)) {
    return fail(error);
  }

  fwds::IssuedFiles files;
  if (!store->issue(type, parser.value(nameOpt), days, caPassphrase, keyPassphrase, &files, &error) ||
      !fwds::writeIssuedFiles(parser.value(outOpt), files, &error)) {
    return fail(error);
  }
  out() << "证书已签发，文件在 " << parser.value(outOpt) << "\n  名称：    " << files.info.name
        << "\n  序列号：  " << files.info.serialHex << "\n  有效期至："
        << files.info.notAfter.toString(Qt::ISODate) << "\n  SHA-256 指纹：" << files.info.fingerprint
        << "\n";
  return 0;
}

int cmdRevoke(const QStringList& args) {
  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("吊销证书并重新生成 crl.pem"));
  const CommonOptions common;
  const QCommandLineOption serialOpt(QStringLiteral("serial"), QStringLiteral("要吊销的证书序列号"),
                                     QStringLiteral("hex"));
  const QCommandLineOption nameOpt(QStringLiteral("name"),
                                   QStringLiteral("吊销该名称下所有未吊销的证书"),
                                   QStringLiteral("name"));
  const QCommandLineOption reasonOpt(QStringLiteral("reason"), QStringLiteral("吊销原因（记入台账）"),
                                     QStringLiteral("text"));
  parser.addOption(serialOpt);
  parser.addOption(nameOpt);
  parser.addOption(reasonOpt);
  std::unique_ptr<CaStore> store;
  if (!openStore(parser, common, args, &store)) return 1;
  if (parser.isSet(serialOpt) == parser.isSet(nameOpt)) {
    return fail(QStringLiteral("--serial 和 --name 必须给且只给一个"));
  }

  SecureBuffer caPassphrase;
  if (!askCaPassphrase(false, &caPassphrase)) return 1;
  int count = 0;
  QString error;
  if (!store->revoke(parser.value(serialOpt), parser.value(nameOpt), parser.value(reasonOpt),
                     caPassphrase, &count, &error)) {
    return fail(error);
  }
  out() << "已吊销 " << count << " 张证书。新的 CRL：" << store->crlPath()
        << "\n请把它分发到服务端和各设备，替换原来的 crl.pem。\n";
  return 0;
}

int cmdUpdateCrl(const QStringList& args) {
  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("重新生成 crl.pem，刷新签发时间、有效期和序号"));
  const CommonOptions common;
  std::unique_ptr<CaStore> store;
  if (!openStore(parser, common, args, &store)) return 1;

  SecureBuffer caPassphrase;
  if (!askCaPassphrase(false, &caPassphrase)) return 1;
  QString error;
  if (!store->updateCrl(caPassphrase, &error)) return fail(error);
  out() << "CRL 已更新：" << store->crlPath() << "\n";
  return 0;
}

int cmdListCerts(const QStringList& args) {
  QCommandLineParser parser;
  parser.setApplicationDescription(QStringLiteral("列出台账里的证书（不需要 CA 口令）"));
  const CommonOptions common;
  std::unique_ptr<CaStore> store;
  if (!openStore(parser, common, args, &store)) return 1;

  QList<fwds::IssuedCert> certs;
  QString error;
  if (!store->list(&certs, &error)) return fail(error);
  for (const fwds::IssuedCert& cert : certs) {
    out() << cert.type.leftJustified(7) << cert.name.leftJustified(24) << cert.serialHex << "  至 "
          << cert.notAfter.toString(Qt::ISODate)
          << (cert.revoked() ? QStringLiteral("  已吊销") : QString()) << "\n";
  }
  out() << "共 " << certs.size() << " 张\n";
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  QCoreApplication app(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("fwds-signer"));
  QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

  QStringList args = app.arguments();
  if (args.size() < 2 || args.at(1) == QLatin1String("--help") || args.at(1) == QLatin1String("-h")) {
    printUsage(out());
    return args.size() < 2 ? 1 : 0;
  }
  // 把子命令名从参数表里拿掉，剩下的交给该子命令自己的解析器
  const QString command = args.takeAt(1);

  if (command == QLatin1String("ca-init")) return cmdCaInit(args);
  if (command == QLatin1String("issue-cert")) return cmdIssueCert(args);
  if (command == QLatin1String("revoke")) return cmdRevoke(args);
  if (command == QLatin1String("update-crl")) return cmdUpdateCrl(args);
  if (command == QLatin1String("list-certs")) return cmdListCerts(args);

  for (const Command& c : kCommands) {
    if (command == QLatin1String(c.name)) {
      err() << "子命令 " << c.name << " 尚未实现\n";
      return 2;
    }
  }
  err() << "未知子命令：" << command << "\n\n";
  printUsage(err());
  return 1;
}
