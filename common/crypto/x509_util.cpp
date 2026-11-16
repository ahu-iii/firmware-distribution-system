#include "common/crypto/x509_util.h"

#include <openssl/pem.h>

namespace fwds {

namespace {

// 把内存 BIO 里已经写入的内容取出来。
QByteArray bioToBytes(BIO* bio) {
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio, &data);
  return size > 0 ? QByteArray(data, static_cast<qsizetype>(size)) : QByteArray();
}

BioPtr bioFromBytes(const QByteArray& bytes) {
  return BioPtr(BIO_new_mem_buf(bytes.constData(), static_cast<int>(bytes.size())));
}

}  // namespace

X509Ptr certFromPem(const QByteArray& pem) {
  const BioPtr bio = bioFromBytes(pem);
  if (!bio) return nullptr;
  return X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

X509Ptr certFromDer(const QByteArray& der) {
  const auto* p = reinterpret_cast<const unsigned char*>(der.constData());
  return X509Ptr(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
}

QByteArray certToPem(X509* cert) {
  const BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) return QByteArray();
  return bioToBytes(bio.get());
}

QByteArray certToDer(X509* cert) {
  const int size = i2d_X509(cert, nullptr);
  if (size <= 0) return QByteArray();
  QByteArray der(size, Qt::Uninitialized);
  auto* p = reinterpret_cast<unsigned char*>(der.data());
  if (i2d_X509(cert, &p) != size) return QByteArray();
  return der;
}

QString certCommonName(X509* cert) {
  X509_NAME* subject = X509_get_subject_name(cert);
  const int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
  if (index < 0) return QString();
  ASN1_STRING* value = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index));
  unsigned char* utf8 = nullptr;
  const int size = ASN1_STRING_to_UTF8(&utf8, value);
  if (size < 0) return QString();
  const QString name = QString::fromUtf8(reinterpret_cast<const char*>(utf8), size);
  OPENSSL_free(utf8);
  return name;
}

QString certSerialHex(X509* cert) {
  const OsslPtr<BIGNUM> bn(ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), nullptr));
  if (!bn) return QString();
  char* hex = BN_bn2hex(bn.get());
  if (!hex) return QString();
  const QString serial = QString::fromLatin1(hex);
  OPENSSL_free(hex);
  return serial;
}

QString certFingerprintSha256(X509* cert) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int size = 0;
  if (X509_digest(cert, EVP_sha256(), digest, &size) != 1) return QString();
  return QString::fromLatin1(
      QByteArray(reinterpret_cast<const char*>(digest), static_cast<qsizetype>(size)).toHex());
}

QDateTime asn1TimeToUtc(const ASN1_TIME* time) {
  struct tm t = {};
  if (!time || ASN1_TIME_to_tm(time, &t) != 1) return QDateTime();
  return QDateTime(QDate(t.tm_year + 1900, t.tm_mon + 1, t.tm_mday),
                   QTime(t.tm_hour, t.tm_min, t.tm_sec), Qt::UTC);
}

QDateTime certNotBefore(X509* cert) { return asn1TimeToUtc(X509_get0_notBefore(cert)); }
QDateTime certNotAfter(X509* cert) { return asn1TimeToUtc(X509_get0_notAfter(cert)); }

X509CrlPtr crlFromPem(const QByteArray& pem) {
  const BioPtr bio = bioFromBytes(pem);
  if (!bio) return nullptr;
  return X509CrlPtr(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
}

QByteArray crlToPem(X509_CRL* crl) {
  const BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509_CRL(bio.get(), crl) != 1) return QByteArray();
  return bioToBytes(bio.get());
}

qint64 crlNumber(X509_CRL* crl) {
  const OsslPtr<ASN1_INTEGER> number(static_cast<ASN1_INTEGER*>(
      X509_CRL_get_ext_d2i(crl, NID_crl_number, nullptr, nullptr)));
  int64_t value = 0;
  if (!number || ASN1_INTEGER_get_int64(&value, number.get()) != 1) return -1;
  return value;
}

EvpPkeyPtr privateKeyFromPkcs8(const SecureBuffer& pkcs8) {
  const unsigned char* p = pkcs8.data();
  const OsslPtr<PKCS8_PRIV_KEY_INFO> info(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, pkcs8.size()));
  if (!info) return nullptr;
  return EvpPkeyPtr(EVP_PKCS82PKEY(info.get()));
}

bool privateKeyToPkcs8(EVP_PKEY* key, SecureBuffer* pkcs8) {
  const OsslPtr<PKCS8_PRIV_KEY_INFO> info(EVP_PKEY2PKCS8(key));
  if (!info) return false;
  const int size = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr);
  if (size <= 0) return false;
  pkcs8->reset(size);
  unsigned char* p = pkcs8->data();  // i2d 会移动这个指针，所以用临时变量
  return i2d_PKCS8_PRIV_KEY_INFO(info.get(), &p) == size;
}

}  // namespace fwds
