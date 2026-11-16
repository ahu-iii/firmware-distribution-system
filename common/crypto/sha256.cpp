#include "common/crypto/sha256.h"

namespace fwds {

QByteArray sha256(const QByteArray& data) {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Sha256::Sha256() : ctx_(EVP_MD_CTX_new()) {
  ok_ = ctx_ && EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) == 1;
}

bool Sha256::update(const QByteArray& data) {
  if (!ok_) return false;
  ok_ = EVP_DigestUpdate(ctx_.get(), data.constData(), static_cast<size_t>(data.size())) == 1;
  return ok_;
}

QByteArray Sha256::finish() {
  if (!ok_) return QByteArray();
  ok_ = false;  // 取过摘要之后上下文不能再用

  QByteArray digest(kSha256Size, '\0');
  unsigned int size = 0;
  if (EVP_DigestFinal_ex(ctx_.get(), reinterpret_cast<unsigned char*>(digest.data()), &size) != 1 ||
      size != static_cast<unsigned int>(kSha256Size)) {
    return QByteArray();
  }
  return digest;
}

}  // namespace fwds
