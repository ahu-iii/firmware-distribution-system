// fwds-signer：离线签发工具（命令行）。
// 这里只搭好子命令框架；各子命令在后续步骤实现（证书相关的属于开发 1，固件相关的属于开发 2）。
#include <QCoreApplication>
#include <QTextStream>

namespace {

struct Command {
  const char* name;
  const char* summary;
};

// 子命令清单，对应设计第 3 节。
const Command kCommands[] = {
    {"ca-init", "生成自建 CA 根密钥和根证书"},
    {"issue-cert", "为服务端或设备签发证书"},
    {"revoke", "吊销证书并更新 CRL"},
    {"sign-fw", "对固件镜像生成 manifest、签名并打包为 .fwpkg"},
    {"sign-exe", "给客户端程序签名"},
    {"issue-lic", "签发设备许可证 device.lic"},
};

void printUsage(QTextStream& out) {
  out << "用法：fwds-signer <子命令> [选项]\n\n子命令：\n";
  for (const Command& c : kCommands) {
    out << "  " << QString::fromLatin1(c.name).leftJustified(12) << QString::fromUtf8(c.summary)
        << "\n";
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  QCoreApplication app(argc, argv);
  QCoreApplication::setApplicationName(QStringLiteral("fwds-signer"));
  QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

  QTextStream out(stdout);
  QTextStream err(stderr);
  const QStringList args = app.arguments();
  if (args.size() < 2 || args.at(1) == QLatin1String("--help") || args.at(1) == QLatin1String("-h")) {
    printUsage(out);
    return args.size() < 2 ? 1 : 0;
  }

  for (const Command& c : kCommands) {
    if (args.at(1) == QLatin1String(c.name)) {
      err << "子命令 " << c.name << " 尚未实现\n";
      return 2;
    }
  }
  err << "未知子命令：" << args.at(1) << "\n\n";
  printUsage(err);
  return 1;
}
