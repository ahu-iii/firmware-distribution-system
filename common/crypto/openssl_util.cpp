#include "common/crypto/openssl_util.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

// 本项目按 OpenSSL 3 的接口编写和测试。机器上同时装了别的大版本（例如 Homebrew 的 openssl@4）时，
// 编译器可能拿到另一版的头文件，而链接的是 3.x 的库，两边对不上。在这里直接停止编译，而不是运行时出怪错。
static_assert(OPENSSL_VERSION_MAJOR == 3,
              "需要 OpenSSL 3.x 的头文件：检查 OPENSSL_ROOT_DIR，macOS 上见 README 的 openssl@3 说明");

namespace fwds {

bool opensslRuntimeIs3() { return OPENSSL_version_major() == 3; }

QString lastOpensslError() {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  if (code == 0) return QStringLiteral("unknown OpenSSL error");
  char text[256];
  ERR_error_string_n(code, text, sizeof(text));
  return QString::fromLatin1(text);
}

}  // namespace fwds
