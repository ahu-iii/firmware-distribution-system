#include "common/crypto/rand.h"

#include <openssl/rand.h>

#include <QtGlobal>

namespace fwds {

QByteArray randomBytes(int size) {
  QByteArray out(size, Qt::Uninitialized);
  if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), size) != 1) {
    qFatal("RAND_bytes failed: system random source unavailable");
  }
  return out;
}

}  // namespace fwds
