#include "common/security/exe_signature.h"

#include <QCoreApplication>
#include <QFile>

#include "common/build_info.h"
#include "common/crypto/rsa_pss.h"
#include "common/crypto/sha256.h"
#include "common/log.h"
#include "common/obfuscated_string.h"

namespace fwds {

QString exeSignaturePath(const QString& exePath) { return exePath + QStringLiteral(".sig"); }

QByteArray exeSignedMessage(const QByteArray& fileSha256) {
  return FWDS_OBF("FWDS-EXE-1") + fileSha256;
}

bool sha256OfFile(const QString& path, QByteArray* digest, QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取 %1").arg(path);
    return false;
  }
  Sha256 hash;
  while (!file.atEnd()) {
    const QByteArray block = file.read(1024 * 1024);
    if (block.isEmpty() || !hash.update(block)) {
      *error = QStringLiteral("读取 %1 出错").arg(path);
      return false;
    }
  }
  *digest = hash.finish();
  return digest->size() == kSha256Size;
}

ExeCheck verifyExecutable(const QString& exePath, const ManifestVerifier& fsk, QString* error) {
  QFile sigFile(exeSignaturePath(exePath));
  if (!sigFile.exists()) {
    *error = QStringLiteral("没有程序签名文件 %1").arg(sigFile.fileName());
    return ExeCheck::Missing;
  }
  // 签名文件固定 384 字节，长度不对的不读
  if (!sigFile.open(QIODevice::ReadOnly) || sigFile.size() != kFskSignatureSize) {
    *error = QString::fromUtf8(FWDS_OBF("程序签名文件格式不对"));
    return ExeCheck::Invalid;
  }
  const QByteArray signature = sigFile.readAll();
  QByteArray digest;
  if (!sha256OfFile(exePath, &digest, error)) return ExeCheck::Invalid;
  if (!fsk.verifySignature(exeSignedMessage(digest), signature)) {
    *error = QString::fromUtf8(FWDS_OBF("程序自校验失败：程序文件或签名被改动过"));
    return ExeCheck::Invalid;
  }
  return ExeCheck::Ok;
}

bool selfCheckExecutable(const ManifestVerifier& fsk, QString* error) {
  const QString exePath = QCoreApplication::applicationFilePath();
  switch (verifyExecutable(exePath, fsk, error)) {
    case ExeCheck::Ok:
      qCInfo(lcSecurity).noquote() << "executable signature verified";
      return true;
    case ExeCheck::Missing:
      if (kRequireExeSignature) return false;
      qCWarning(lcApp).noquote() << *error << "- development build, self check skipped";
      return true;
    case ExeCheck::Invalid:
      return false;
  }
  return false;
}

}  // namespace fwds
