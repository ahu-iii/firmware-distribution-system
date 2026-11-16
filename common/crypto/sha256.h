// SHA-256（设计第 3 节 crypto::sha256）：固件整镜像哈希、分片哈希、公钥指纹都用它。
// 只调用 OpenSSL EVP 接口，不自己实现算法。
#pragma once

#include <QByteArray>

#include "common/crypto/openssl_util.h"

namespace fwds {

inline constexpr int kSha256Size = 32;  // 摘要长度（字节）

// 一次算完：返回 32 字节摘要；OpenSSL 报错时返回空数组。
QByteArray sha256(const QByteArray& data);

// 分多次喂数据的 SHA-256。镜像可能有上百 MB，不能整个读进内存，所以一片一片地喂。
// 用法：update() 若干次，最后 finish() 取摘要；finish() 之后对象不能再用。
class Sha256 {
 public:
  Sha256();

  // 追加一段数据。返回 false 表示 OpenSSL 报错，之后 finish() 返回空数组。
  bool update(const QByteArray& data);

  // 取出摘要（32 字节）。中途出过错返回空数组。
  QByteArray finish();

 private:
  OsslPtr<EVP_MD_CTX> ctx_;
  bool ok_ = false;
};

}  // namespace fwds
