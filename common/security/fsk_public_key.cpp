#include "common/security/fsk_public_key.h"

#include <QFile>

namespace fwds {

bool loadPinnedFskPublicKey(const QString& pemPath, const QString& expectedSha256,
                            ManifestVerifier* verifier, QString* error) {
  QFile file(pemPath);
  // RSA-3072 公钥的 PEM 约 600 字节；先看大小，超过 16 KB 的不读
  if (!file.open(QIODevice::ReadOnly) || file.size() > 16 * 1024) {
    *error = QStringLiteral("无法读取固件签名公钥 %1").arg(pemPath);
    return false;
  }
  // 先装进一个临时的验签器，指纹核对通过才交给调用方
  ManifestVerifier candidate;
  if (!candidate.loadPublicKey(file.readAll(), error)) return false;
  if (candidate.publicKeyFingerprint() != expectedSha256) {
    *error = QStringLiteral("固件签名公钥的指纹与配置 fsk_pub_sha256 不一致（文件指纹前 8 位 %1）")
                 .arg(candidate.publicKeyFingerprint().left(8));
    return false;
  }
  *verifier = std::move(candidate);
  return true;
}

}  // namespace fwds
