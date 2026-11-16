#include "common/crypto/rsa_pss.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "common/crypto/sha256.h"

namespace fwds {

namespace {

const unsigned char* bytes(const QByteArray& a) {
  return reinterpret_cast<const unsigned char*>(a.constData());
}

// 把签名 / 验签上下文配置成 PSS。三个参数签名方和验签方必须完全一致。
bool configurePss(EVP_PKEY_CTX* pctx) {
  // 填充方式选 PSS（默认是老的 PKCS#1 v1.5）
  if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) return false;
  // 盐长固定为摘要长度 32 字节。验签时不用“自动识别盐长”，签名里的盐长不是 32 就判失败
  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) return false;
  // 掩码生成函数 MGF1 也用 SHA-256
  return EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) == 1;
}

}  // namespace

bool isRsa3072(EVP_PKEY* key) {
  return key && EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA && EVP_PKEY_get_bits(key) == kFskKeyBits;
}

bool rsaPssSign(EVP_PKEY* privateKey, const QByteArray& message, QByteArray* signature,
                QString* error) {
  signature->clear();
  if (!isRsa3072(privateKey)) {
    *error = QStringLiteral("签名密钥不是 RSA-3072");
    return false;
  }

  const OsslPtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;  // 归 ctx 所有，随 ctx 一起释放
  if (!ctx || EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, privateKey) != 1 ||
      !configurePss(pctx)) {
    *error = QStringLiteral("初始化签名失败：%1").arg(lastOpensslError());
    return false;
  }

  // 第一次调用只问签名有多长，第二次才真正签
  size_t size = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &size, bytes(message),
                     static_cast<size_t>(message.size())) != 1) {
    *error = QStringLiteral("签名失败：%1").arg(lastOpensslError());
    return false;
  }
  QByteArray out(static_cast<qsizetype>(size), '\0');
  if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(out.data()), &size, bytes(message),
                     static_cast<size_t>(message.size())) != 1 ||
      size != static_cast<size_t>(kFskSignatureSize)) {
    *error = QStringLiteral("签名失败：%1").arg(lastOpensslError());
    return false;
  }
  *signature = out;
  return true;
}

bool rsaPssVerify(EVP_PKEY* publicKey, const QByteArray& message, const QByteArray& signature) {
  if (!isRsa3072(publicKey) || signature.size() != kFskSignatureSize) return false;

  const OsslPtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, publicKey) != 1 ||
      !configurePss(pctx)) {
    lastOpensslError();  // 清掉错误队列
    return false;
  }
  // 返回 1 才是验签通过；0 是签名不符，负数是出错，都按失败处理
  const int rc = EVP_DigestVerify(ctx.get(), bytes(signature), static_cast<size_t>(signature.size()),
                                  bytes(message), static_cast<size_t>(message.size()));
  if (rc != 1) lastOpensslError();
  return rc == 1;
}

EvpPkeyPtr publicKeyFromPem(const QByteArray& pem) {
  const BioPtr bio(BIO_new_mem_buf(pem.constData(), static_cast<int>(pem.size())));
  if (!bio) return nullptr;
  return EvpPkeyPtr(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
}

QByteArray publicKeyToPem(EVP_PKEY* key) {
  const BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_PUBKEY(bio.get(), key) != 1) return QByteArray();
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &data);
  return size > 0 ? QByteArray(data, static_cast<qsizetype>(size)) : QByteArray();
}

QString publicKeyFingerprintSha256(EVP_PKEY* key) {
  // i2d_PUBKEY 输出 SubjectPublicKeyInfo 的 DER 编码，同一把公钥的编码是唯一的
  const int size = i2d_PUBKEY(key, nullptr);
  if (size <= 0) return QString();
  QByteArray der(size, '\0');
  auto* p = reinterpret_cast<unsigned char*>(der.data());
  if (i2d_PUBKEY(key, &p) != size) return QString();
  return QString::fromLatin1(sha256(der).toHex());
}

}  // namespace fwds
