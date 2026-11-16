#include "common/crypto/kdf.h"

#include <openssl/evp.h>

namespace fwds {

bool pbkdf2Sha256(const SecureBuffer& passphrase, const QByteArray& salt, int iterations,
                  int keySize, SecureBuffer* key) {
  if (passphrase.isEmpty() || salt.isEmpty() || iterations < 1 || keySize < 1) return false;
  key->reset(keySize);
  const int ok = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(passphrase.data()),
                                   passphrase.size(),
                                   reinterpret_cast<const unsigned char*>(salt.constData()),
                                   static_cast<int>(salt.size()), iterations, EVP_sha256(),
                                   keySize, key->data());
  if (ok != 1) {
    key->reset(0);
    return false;
  }
  return true;
}

}  // namespace fwds
