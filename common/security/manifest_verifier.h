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
#include "common/crypto/sha256.h"
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

// 分段核对整镜像时每一段查多少片：16 片约 1 MB。
inline constexpr int kImageCheckStepChunks = 16;

// 整镜像核对，分段进行：从 image 的当前位置顺序读，逐片核对分片哈希，同时累计整镜像哈希，
// 读完最后一片再核对整镜像哈希。读到的字节数少于 image_size 也算失败。
// 每次只读一片，不把镜像整个放进内存；每次 step() 只查几片，调用方可以在两次之间回到事件循环
// （设备端升级时界面不卡）。image 和 manifest 必须比本对象活得久。
class ImageCheck {
 public:
  enum class Step {
    More,    // 还没查完，继续调用 step()
    Passed,  // 全部分片和整镜像哈希都与 manifest 一致
    Failed,  // 有不一致，error 里是原因
  };

  ImageCheck(QIODevice* image, const Manifest& manifest);

  // 再核对最多 maxChunks 片。返回 Passed 或 Failed 之后不要再调用。
  Step step(int maxChunks, QString* error);

  // 已经核对通过的片数（算进度用）。
  int checkedChunks() const { return next_; }

 private:
  QIODevice* image_;
  const Manifest& manifest_;
  Sha256 whole_;  // 整镜像哈希，和分片哈希同时算，镜像只读一遍
  int next_ = 0;  // 下一个要核对的分片
};

// 一口气核对完整个镜像（ImageCheck 循环到底）。服务端导入固件、Bootloader 启动检查用。
bool verifyImage(QIODevice* image, const Manifest& manifest, QString* error);

}  // namespace fwds
