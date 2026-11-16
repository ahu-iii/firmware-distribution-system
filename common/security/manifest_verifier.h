// ManifestVerifier：用 FSK 公钥验证固件的可信性（设计第 12 章）。
// 三个层次，对应设计 12.2 节流程图里的三处检查：
//   1. verify()        下载之前：对 manifest 原始字节验签，通过后才解析 JSON；
//   2. chunkMatches()  下载过程中：每收到一片就和 manifest 里的分片哈希比对；
//   3. verifyImage()   写入之前 / 启动之前：把整个镜像从头到尾重算一遍。
// 服务端导入固件包、设备端升级、Bootloader 启动检查用的是同一份代码。
#pragma once

#include <QByteArray>
#include <QIODevice>
#include <QString>

#include "common/crypto/openssl_util.h"
#include "common/manifest.h"

namespace fwds {

// verify() 的结论。
enum class ManifestCheck {
  Ok,
  BadSignature,  // 签名不是 FSK 对这份字节签的：manifest 被改过、签名被换过或是伪造的
  BadContent,    // 签名正确，但内容不合规：格式版本不支持、字段缺失或互相矛盾
};

class ManifestVerifier {
 public:
  // 装入 FSK 公钥（PEM）。不是 RSA-3072 公钥则拒绝。
  bool loadPublicKey(const QByteArray& pem, QString* error);

  // 公钥指纹（SHA-256，小写十六进制），显示给操作人员核对。还没装入公钥时为空串。
  QString publicKeyFingerprint() const;

  // 先验签、后解析。只有返回 Ok 时 out 才被写入；
  // 返回 BadSignature 时 JSON 解析器根本没有被调用，不可信的字节不会进入解析器。
  ManifestCheck verify(const QByteArray& manifestRaw, const QByteArray& signature, Manifest* out,
                       QString* error) const;

 private:
  EvpPkeyPtr publicKey_;
};

// 第 index 片的数据是否与 manifest 一致：下标在范围内、长度正确、SHA-256 相同。
// manifest 必须是 verify() 返回 Ok 得到的。
bool chunkMatches(const Manifest& manifest, int index, const QByteArray& data);

// 从 image 的当前位置顺序读出整个镜像，逐片核对分片哈希，最后核对整镜像哈希。
// 读到的字节数少于 image_size 也算失败。每次只读一片，不把镜像整个放进内存。
bool verifyImage(QIODevice* image, const Manifest& manifest, QString* error);

}  // namespace fwds
