#include "client/business/demo_actions.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <cstdlib>

#include "common/log.h"

namespace fwds {

bool tamperDownloadCache(const QString& dataDir, QString* detail) {
  const QDir download(QDir(dataDir).filePath(QStringLiteral("download")));
  const QFileInfoList parts =
      download.entryInfoList({QStringLiteral("*.part")}, QDir::Files, QDir::Time);  // 新的在前
  if (parts.isEmpty()) {
    *detail = QStringLiteral("没有下载缓存（只有下载中或断点暂停时才有 .part 文件）");
    return false;
  }
  QFile file(parts.first().absoluteFilePath());
  if (!file.open(QIODevice::ReadWrite) || file.size() == 0) {
    *detail = QStringLiteral("无法打开 %1").arg(parts.first().fileName());
    return false;
  }
  // 第一片最先下载，改它的第一个字节：这一片已经校验过、写进了缓存，之后再没人看过它
  char byte = 0;
  file.getChar(&byte);
  file.seek(0);
  file.putChar(static_cast<char>(~byte));
  file.close();
  *detail = QStringLiteral("已把 %1 的第 1 个字节取反").arg(parts.first().fileName());
  qCWarning(lcApp).noquote() << "demo panel: download cache tampered," << parts.first().fileName();
  return true;
}

void simulatePowerLoss() {
  qCWarning(lcApp) << "demo panel: simulated power loss, process ends now";
  // _Exit：不调用析构函数和 atexit，不发 BYE。日志每条写完就刷了盘，所以这一条也在文件里
  std::_Exit(kPowerLossExitCode);
}

}  // namespace fwds
