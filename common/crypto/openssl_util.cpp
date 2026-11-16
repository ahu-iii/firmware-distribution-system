#include "common/crypto/openssl_util.h"

#include <openssl/err.h>

namespace fwds {

QString lastOpensslError() {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  if (code == 0) return QStringLiteral("unknown OpenSSL error");
  char text[256];
  ERR_error_string_n(code, text, sizeof(text));
  return QString::fromLatin1(text);
}

}  // namespace fwds
