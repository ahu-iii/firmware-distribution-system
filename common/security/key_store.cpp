#include "common/security/key_store.h"

#include <QFile>
#include <cstdlib>
#include <cstring>

#include "common/crypto/key_file.h"

namespace fwds {

bool takePassphraseFromEnv(const char* name, SecureBuffer* passphrase) {
  QByteArray value = qgetenv(name);
  // 先把进程环境块里的原始字节抹掉再删除变量：只调 unsetenv 时原字符串还留在内存里，
  // Linux 上 /proc/<pid>/environ 仍能读到口令
  if (char* raw = std::getenv(name)) OPENSSL_cleanse(raw, std::strlen(raw));
  qunsetenv(name);  // 之后启动的子进程、崩溃转储里的环境块都不再带着口令
  if (value.isEmpty()) return false;
  *passphrase = SecureBuffer::fromBytes(value.constData(), static_cast<int>(value.size()));
  OPENSSL_cleanse(value.data(), static_cast<size_t>(value.size()));
  return true;
}

bool loadSealedKeyFile(const QString& path, const SecureBuffer& passphrase, SecureBuffer* pkcs8,
                       QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取私钥文件：%1").arg(path);
    return false;
  }
  // 文件大小先和上限比，再读进内存
  if (file.size() > kKeyFileHeaderSize + kKeyFileMaxCiphertext + 16) {
    *error = QStringLiteral("私钥文件过大：%1").arg(path);
    return false;
  }
  return openPrivateKey(file.readAll(), passphrase, pkcs8, error);
}

}  // namespace fwds
