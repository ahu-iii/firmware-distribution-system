// FskStore：签发主机上的固件签名密钥目录（设计 11.3 节密钥清单里的 FSK）。
// 目录内容：
//   fsk.key      FSK 私钥（RSA-3072），AES-256-GCM 封装，口令每次使用时人工输入
//   fsk.pub.pem  FSK 公钥（公开）：装进设备客户端用于验签，服务端导入固件包时也用它
// 和 CA 目录一样只存在于离线的签发主机上，不进仓库。私钥明文不落盘。
#pragma once

#include <QString>

#include "common/crypto/kdf.h"
#include "common/crypto/openssl_util.h"
#include "common/crypto/secure_buffer.h"

namespace fwds {

// 生成一对 RSA-3072 密钥，公开指数 65537。失败返回空指针。
EvpPkeyPtr generateRsa3072Key();

class FskStore {
 public:
  explicit FskStore(const QString& dir, int kdfIterations = kKdfDefaultIterations);

  QString privateKeyPath() const;
  QString publicKeyPath() const;

  // fsk-init：生成 FSK 密钥对，私钥用口令封装后写盘，公钥写成 PEM。目录里已有 FSK 时拒绝覆盖。
  // fingerprint 返回公钥指纹，供操作人员记录和核对。
  bool init(const SecureBuffer& passphrase, QString* fingerprint, QString* error);

  // 用口令解开私钥。口令错误或文件被改动时失败。
  bool loadPrivateKey(const SecureBuffer& passphrase, EvpPkeyPtr* key, QString* error) const;

 private:
  QString dir_;
  int kdfIterations_;
};

}  // namespace fwds
