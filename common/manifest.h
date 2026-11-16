// Manifest：固件元数据清单（协议文档 7.1 节，设计 12.1 节）。
// 固件包里被 RSA 签名的只有 manifest，但 manifest 里写着整镜像哈希和每一片的哈希，
// 所以镜像改动任何一个字节，都会和受签名保护的哈希对不上。
//
// 这个文件只管“字段、序列化、解析和字段检查”，不涉及密钥。
// 验签在 common/security/manifest_verifier：先对原始字节验签，通过后才调用这里的 parseManifest。
#pragma once

#include <QByteArray>
#include <QList>
#include <QString>

namespace fwds {

inline constexpr int kManifestFormat = 1;                        // manifest 格式版本
inline constexpr int kChunkSize = 65536;                         // 分片大小，固定 64 KB
inline constexpr qint64 kMaxImageSize = 256LL * 1024 * 1024;     // 镜像上限 256 MB（4096 片）
// manifest 原始字节上限 512 KB。UPDATE_NOTIFY 把 manifest 做成 Base64 放进一帧，
// Base64 会膨胀到 4/3 倍，512 KB 膨胀后约 683 KB，仍在 1 MB 的帧长上限之内。
inline constexpr int kMaxManifestSize = 512 * 1024;
inline constexpr int kMaxReleaseNoteLength = 1024;               // 发布说明的字符数上限

// 版本号 “主.次.修订”，例如 2.1.0。
struct FirmwareVersion {
  int major = 0;
  int minor = 0;
  int patch = 0;
};

// 解析版本号。必须正好是三段十进制数字，每段 0 ~ 9999，不允许前导零、空格、正负号。
bool parseFirmwareVersion(const QString& text, FirmwareVersion* out);

// 比较两个版本号：a 比 b 旧返回负数，相同返回 0，a 比 b 新返回正数。
int compareFirmwareVersion(const FirmwareVersion& a, const FirmwareVersion& b);

struct Manifest {
  int format = kManifestFormat;
  QString pkgId;                  // 包 ID，小写 UUID；后面会用它拼断点文件名，所以字符集卡死
  QString deviceModel;            // 适用型号，设备只接受和自己型号一致的包
  QString version;                // 版本号 “主.次.修订”
  int securityVersion = 0;        // 安全版本号，只增不减，防降级用（设计 12.2 节）
  qint64 imageSize = 0;           // 镜像字节数
  QByteArray imageSha256;         // 整镜像 SHA-256（32 字节原始摘要）
  int chunkSize = kChunkSize;
  int chunkCount = 0;
  QList<QByteArray> chunkSha256;  // 每一片的 SHA-256（32 字节原始摘要），下标就是分片序号
  QString buildTime;              // 签发时间，ISO 8601（UTC）
  QString releaseNote;            // 发布说明

  // 第 index 片应有的字节数：最后一片可能不满 64 KB，其余都是 chunkSize。下标越界返回 -1。
  qint64 chunkLength(int index) const;
};

// imageSize 字节的镜像要分成多少片（向上取整）。
int chunkCountFor(qint64 imageSize);

// 检查各字段的取值范围和相互关系（片数 = 镜像大小 ÷ 片大小向上取整、哈希个数 = 片数……）。
// 签发工具签名之前调用一次，解析之后也调用一次，两头用的是同一套规则。
bool checkManifest(const Manifest& manifest, QString* error);

// 序列化成 JSON 字节串。签名针对的就是这串字节，之后任何环节都原样传递、原样保存，
// 不重新序列化（重新序列化可能改变字段顺序或空白，签名就对不上了）。
QByteArray serializeManifest(const Manifest& manifest);

// 解析 JSON 并做 checkManifest。字段缺失、类型不对、取值越界都返回 false。
// 注意：这个函数不验签。输入必须是已经验过签名的字节，见 ManifestVerifier。
bool parseManifest(const QByteArray& raw, Manifest* out, QString* error);

}  // namespace fwds
