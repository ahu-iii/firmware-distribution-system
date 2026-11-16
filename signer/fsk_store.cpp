#include "signer/fsk_store.h"

#include <openssl/rsa.h>

#include <QDir>
#include <QFile>

#include "common/crypto/key_file.h"
#include "common/crypto/rsa_pss.h"
#include "common/crypto/x509_util.h"
#include "common/security/key_store.h"
#include "signer/ca_store.h"

namespace fwds {

EvpPkeyPtr generateRsa3072Key() {
  const OsslPtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  // 公开指数用 OpenSSL 的默认值 65537
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), kFskKeyBits) != 1) {
    return nullptr;
  }
  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) != 1) return nullptr;
  return EvpPkeyPtr(key);
}

FskStore::FskStore(const QString& dir, int kdfIterations)
    : dir_(dir), kdfIterations_(kdfIterations) {}

QString FskStore::privateKeyPath() const { return QDir(dir_).filePath(QStringLiteral("fsk.key")); }
QString FskStore::publicKeyPath() const { return QDir(dir_).filePath(QStringLiteral("fsk.pub.pem")); }

bool FskStore::init(const SecureBuffer& passphrase, QString* fingerprint, QString* error) {
  if (QFile::exists(privateKeyPath()) || QFile::exists(publicKeyPath())) {
    *error = QStringLiteral("%1 里已经有固件签名密钥，拒绝覆盖").arg(dir_);
    return false;
  }
  if (!isAcceptablePassphrase(passphrase)) {
    *error = QStringLiteral("FSK 口令至少 %1 个字符").arg(kMinPassphraseLength);
    return false;
  }
  if (!QDir().mkpath(dir_)) {
    *error = QStringLiteral("无法创建目录 %1").arg(dir_);
    return false;
  }

  const EvpPkeyPtr key = generateRsa3072Key();
  if (!key) {
    *error = QStringLiteral("生成 FSK 密钥失败：%1").arg(lastOpensslError());
    return false;
  }

  // 私钥：PKCS#8 明文只在 SecureBuffer 里出现，封装成密文后才写盘，明文随 SecureBuffer 析构清零
  SecureBuffer pkcs8;
  if (!privateKeyToPkcs8(key.get(), &pkcs8)) {
    *error = QStringLiteral("私钥编码失败：%1").arg(lastOpensslError());
    return false;
  }
  QByteArray sealed;
  if (!sealPrivateKey(pkcs8, passphrase, &sealed, error, kdfIterations_)) return false;

  const QByteArray publicPem = publicKeyToPem(key.get());
  if (publicPem.isEmpty()) {
    *error = QStringLiteral("公钥编码失败：%1").arg(lastOpensslError());
    return false;
  }
  if (!writeFileAtomic(privateKeyPath(), sealed, true, error) ||
      !writeFileAtomic(publicKeyPath(), publicPem, false, error)) {
    return false;
  }
  *fingerprint = publicKeyFingerprintSha256(key.get());
  return true;
}

bool FskStore::loadPrivateKey(const SecureBuffer& passphrase, EvpPkeyPtr* key,
                              QString* error) const {
  SecureBuffer pkcs8;
  if (!loadSealedKeyFile(privateKeyPath(), passphrase, &pkcs8, error)) return false;
  EvpPkeyPtr loaded = privateKeyFromPkcs8(pkcs8);
  if (!loaded || !isRsa3072(loaded.get())) {
    lastOpensslError();  // 清掉错误队列
    *error = QStringLiteral("fsk.key 里不是 RSA-3072 私钥");
    return false;
  }
  *key = std::move(loaded);
  return true;
}

}  // namespace fwds
