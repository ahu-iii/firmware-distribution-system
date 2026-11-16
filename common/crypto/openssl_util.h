// OpenSSL 对象的智能指针和错误信息（设计第 16 节：对象用智能指针管理，每个调用检查返回值）。
#pragma once

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <QString>
#include <memory>

namespace fwds {

// 每种 OpenSSL 对象对应自己的释放函数。
struct OsslDeleter {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
  void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
  void operator()(X509* p) const { X509_free(p); }
  void operator()(X509_CRL* p) const { X509_CRL_free(p); }
  void operator()(X509_REVOKED* p) const { X509_REVOKED_free(p); }
  void operator()(X509_STORE* p) const { X509_STORE_free(p); }
  void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); }
  void operator()(X509_EXTENSION* p) const { X509_EXTENSION_free(p); }
  void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); }
  // ASN1_INTEGER、ASN1_TIME 在 OpenSSL 里是同一个结构体的别名，共用这一个释放函数
  void operator()(ASN1_STRING* p) const { ASN1_STRING_free(p); }
  void operator()(BIGNUM* p) const { BN_free(p); }
  void operator()(BIO* p) const { BIO_free_all(p); }
};

template <class T>
using OsslPtr = std::unique_ptr<T, OsslDeleter>;

using EvpPkeyPtr = OsslPtr<EVP_PKEY>;
using X509Ptr = OsslPtr<X509>;
using X509CrlPtr = OsslPtr<X509_CRL>;
using BioPtr = OsslPtr<BIO>;

// 取出并清空 OpenSSL 错误队列，返回最早一条的文字说明。只含库名和原因，不含密钥数据。
QString lastOpensslError();

}  // namespace fwds
