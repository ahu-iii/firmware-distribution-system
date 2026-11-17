// 设备端装入固件签名公钥（FSK 公钥）。
// 公钥不是秘密，随设备出厂写入一个 PEM 文件；但“设备信任哪一把公钥”决定了它肯装谁签的固件，
// 所以配置里另外写着这把公钥的指纹（公钥 DER 的 SHA-256，fsk-init 生成密钥时显示），
// 启动时文件算出的指纹和配置对不上就拒绝运行（设计 11.3 节）。
#pragma once

#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

// 读 pemPath，确认是 RSA-3072 公钥且指纹等于 expectedSha256（64 个小写十六进制字符），
// 通过后装进 verifier。失败时 verifier 里没有公钥，任何固件都验不过。
bool loadPinnedFskPublicKey(const QString& pemPath, const QString& expectedSha256,
                            ManifestVerifier* verifier, QString* error);

}  // namespace fwds
