#include "common/security/manifest_verifier.h"

#include "common/crypto/rsa_pss.h"
#include "common/crypto/sha256.h"

namespace fwds {

bool ManifestVerifier::loadPublicKey(const QByteArray& pem, QString* error) {
  EvpPkeyPtr key = publicKeyFromPem(pem);
  if (!key) {
    lastOpensslError();  // 清掉错误队列
    *error = QStringLiteral("无法解析固件签名公钥");
    return false;
  }
  if (!isRsa3072(key.get())) {
    *error = QStringLiteral("固件签名公钥不是 RSA-3072");
    return false;
  }
  publicKey_ = std::move(key);
  return true;
}

QString ManifestVerifier::publicKeyFingerprint() const {
  return publicKey_ ? publicKeyFingerprintSha256(publicKey_.get()) : QString();
}

ManifestCheck ManifestVerifier::verify(const QByteArray& manifestRaw, const QByteArray& signature,
                                       Manifest* out, QString* error) const {
  // 第一步：验签。没装公钥、签名不符都在这里返回，后面的解析不会执行
  if (!publicKey_ || !rsaPssVerify(publicKey_.get(), manifestRaw, signature)) {
    *error = QStringLiteral("manifest 签名验证失败");
    return ManifestCheck::BadSignature;
  }
  // 第二步：字节已经确认出自 FSK，才交给 JSON 解析器并检查字段
  if (!parseManifest(manifestRaw, out, error)) return ManifestCheck::BadContent;
  return ManifestCheck::Ok;
}

bool chunkMatches(const Manifest& manifest, int index, const QByteArray& data) {
  // chunkLength 对越界的下标返回 -1，和任何长度都不相等
  if (data.size() != manifest.chunkLength(index)) return false;
  return sha256(data) == manifest.chunkSha256.at(index);
}

bool verifyImage(QIODevice* image, const Manifest& manifest, QString* error) {
  Sha256 whole;  // 整镜像哈希，和分片哈希同时算，只读一遍
  for (int index = 0; index < manifest.chunkCount; ++index) {
    const qint64 expected = manifest.chunkLength(index);
    const QByteArray chunk = image->read(expected);
    if (chunk.size() != expected) {
      *error = QStringLiteral("镜像长度不足：第 %1 片读不满").arg(index);
      return false;
    }
    if (!chunkMatches(manifest, index, chunk)) {
      *error = QStringLiteral("第 %1 片的哈希与 manifest 不符").arg(index);
      return false;
    }
    whole.update(chunk);
  }
  if (whole.finish() != manifest.imageSha256) {
    *error = QStringLiteral("整镜像哈希与 manifest 不符");
    return false;
  }
  return true;
}

}  // namespace fwds
