#include "common/crypto/openssl_util.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

// 本项目按 OpenSSL 3 的 EVP 接口编写，OpenSSL 4 也能编译通过（macOS 上 Homebrew 的 Qt 已改用 4）。
// 更老的 1.1 没有这些接口，在这里直接停止编译，而不是运行时出怪错。
static_assert(OPENSSL_VERSION_MAJOR >= 3,
              "需要 OpenSSL 3 或更新版本的头文件：检查 OPENSSL_ROOT_DIR，macOS 上见 README 的说明");

namespace fwds {

int opensslRuntimeMajor() { return static_cast<int>(OPENSSL_version_major()); }

QString lastOpensslError() {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  if (code == 0) return QStringLiteral("unknown OpenSSL error");
  char text[256];
  ERR_error_string_n(code, text, sizeof(text));
  return QString::fromLatin1(text);
}

}  // namespace fwds
