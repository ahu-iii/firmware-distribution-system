// 装入固件签名公钥（FSK 公钥）。设备端和服务端都用它：设备靠它决定装不装一份固件，
// 服务端靠它决定一个固件包能不能进固件库。
// 公钥不是秘密，部署时放成一个 PEM 文件；但“信任哪一把公钥”决定了肯认谁签的固件，
// 所以配置里另外写着这把公钥的指纹（公钥 DER 的 SHA-256，fsk-init 生成密钥时显示），
// 启动时文件算出的指纹和配置对不上就拒绝运行（设计 11.3 节）。两端的配置项名字相同：
// [client] 或 [server] 段里的 fsk_pub_file、fsk_pub_sha256。
#pragma once

#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

// 读 pemPath，确认是 RSA-3072 公钥且指纹等于 expectedSha256（64 个小写十六进制字符），
// 通过后装进 verifier。失败时 verifier 里没有公钥，任何固件都验不过。
bool loadPinnedFskPublicKey(const QString& pemPath, const QString& expectedSha256,
                            ManifestVerifier* verifier, QString* error);

}  // namespace fwds
