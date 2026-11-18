#include "common/security/manifest_verifier.h"

#include "common/crypto/rsa_pss.h"

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

bool ManifestVerifier::verifySignature(const QByteArray& message,
                                       const QByteArray& signature) const {
  return publicKey_ && rsaPssVerify(publicKey_.get(), message, signature);
}

bool chunkMatches(const Manifest& manifest, int index, const QByteArray& data) {
  // chunkLength 对越界的下标返回 -1，和任何长度都不相等
  if (data.size() != manifest.chunkLength(index)) return false;
  return sha256(data) == manifest.chunkSha256.at(index);
}

ImageCheck::ImageCheck(QIODevice* image, const Manifest& manifest)
    : image_(image), manifest_(manifest) {}

ImageCheck::Step ImageCheck::step(int maxChunks, QString* error) {
  const int end = qMin(manifest_.chunkCount, next_ + maxChunks);
  for (; next_ < end; ++next_) {
    const qint64 expected = manifest_.chunkLength(next_);
    const QByteArray chunk = image_->read(expected);
    if (chunk.size() != expected) {
      *error = QStringLiteral("镜像长度不足：第 %1 片读不满").arg(next_);
      return Step::Failed;
    }
    if (!chunkMatches(manifest_, next_, chunk)) {
      *error = QStringLiteral("第 %1 片的哈希与 manifest 不符").arg(next_);
      return Step::Failed;
    }
    whole_.update(chunk);
  }
  if (next_ < manifest_.chunkCount) return Step::More;

  if (whole_.finish() != manifest_.imageSha256) {
    *error = QStringLiteral("整镜像哈希与 manifest 不符");
    return Step::Failed;
  }
  return Step::Passed;
}

bool verifyImage(QIODevice* image, const Manifest& manifest, QString* error) {
  ImageCheck check(image, manifest);
  ImageCheck::Step result = ImageCheck::Step::More;
  while (result == ImageCheck::Step::More) result = check.step(kImageCheckStepChunks, error);
  return result == ImageCheck::Step::Passed;
}

}  // namespace fwds
