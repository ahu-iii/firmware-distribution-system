// 固件签名相关测试共用的材料：运行测试时现场生成的 RSA-3072 密钥，仓库里不存放任何测试私钥。
#pragma once

#include <QBuffer>
#include <QByteArray>

#include "common/crypto/rand.h"
#include "common/crypto/rsa_pss.h"
#include "common/manifest.h"
#include "common/security/manifest_verifier.h"
#include "signer/firmware_packer.h"
#include "signer/fsk_store.h"

namespace fwds_test {

// 一对 FSK 密钥和它的公钥 PEM。
struct TestFsk {
  fwds::EvpPkeyPtr key = fwds::generateRsa3072Key();
  QByteArray publicPem = fwds::publicKeyToPem(key.get());
};

// 正常的签发方。生成 RSA-3072 要一两秒，所以全部测试共用一把。
inline TestFsk& sharedFsk() {
  static TestFsk instance;
  return instance;
}

// 攻击者自己生成的另一把 RSA-3072 密钥（对应 attack_tools/fake_signer）。
inline TestFsk& attackerFsk() {
  static TestFsk instance;
  return instance;
}

// 装好 sharedFsk 公钥的验签器。
inline fwds::ManifestVerifier trustedVerifier() {
  fwds::ManifestVerifier verifier;
  QString error;
  verifier.loadPublicKey(sharedFsk().publicPem, &error);
  return verifier;
}

// 翻转第 index 个字节的最低位。
inline QByteArray flipBit(QByteArray bytes, qsizetype index) {
  bytes[index] = static_cast<char>(bytes[index] ^ 0x01);
  return bytes;
}

// 测试用的固件元数据。
inline fwds::FirmwareInfo sampleInfo() {
  fwds::FirmwareInfo info;
  info.deviceModel = QStringLiteral("PLC-X200");
  info.version = QStringLiteral("2.1.0");
  info.securityVersion = 5;
  info.releaseNote = QStringLiteral("unit test firmware");
  return info;
}

// 为一段镜像字节生成 manifest（和签发工具走同一个函数）。
inline fwds::Manifest manifestFor(const QByteArray& image,
                                  const fwds::FirmwareInfo& info = sampleInfo()) {
  QBuffer buffer;
  buffer.setData(image);
  buffer.open(QIODevice::ReadOnly);
  fwds::Manifest manifest;
  QString error;
  fwds::buildManifest(&buffer, info, &manifest, &error);
  return manifest;
}

// 用给定的密钥对一串字节签名。
inline QByteArray signWith(const TestFsk& fsk, const QByteArray& message) {
  QByteArray signature;
  QString error;
  fwds::rsaPssSign(fsk.key.get(), message, &signature, &error);
  return signature;
}

}  // namespace fwds_test
