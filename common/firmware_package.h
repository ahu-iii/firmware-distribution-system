// .fwpkg 固件包容器（协议文档 7.2 节）。多字节整数为大端。
//   字段          长度           说明
//   magic         4              ASCII "FWPK"
//   format        2              容器格式版本，当前为 1
//   manifest_len  4              manifest 字节数（≤ 512 KB）
//   manifest      manifest_len   manifest.json 原始字节
//   sig_len       2              签名字节数（RSA-3072 为 384）
//   sig           sig_len        RSA-PSS-SHA256(manifest)
//   image_len     8              镜像字节数，必须等于 manifest.image_size
//   image         image_len      固件镜像
// 解析时每个长度字段都先和上限、再和文件剩余长度核对，之后才按它读取。
#pragma once

#include <QByteArray>
#include <QIODevice>
#include <QString>

#include "common/manifest.h"
#include "common/security/manifest_verifier.h"

namespace fwds {

inline constexpr int kMaxPackageSignatureSize = 1024;  // sig_len 的上限，先校验再读取

// 容器里镜像之前的部分，以及镜像在文件里的位置。
struct PackageHeader {
  QByteArray manifestRaw;  // 原样取出，验签针对的就是这串字节
  QByteArray signature;
  qint64 imageOffset = 0;  // 镜像第一个字节在文件里的偏移
  qint64 imageSize = 0;    // image_len 字段的值
};

// 生成镜像之前的全部字节（magic 到 image_len）。签发工具写文件时先写它，再接着写镜像。
QByteArray buildPackageHeader(const QByteArray& manifestRaw, const QByteArray& signature,
                              qint64 imageSize);

// 从文件开头解析容器头。file 必须已打开且可随机访问（能取得总长度）。
// 只做结构检查，不验签；成功后 file 的读位置停在镜像第一个字节。
bool readPackageHeader(QIODevice* file, PackageHeader* out, QString* error);

// 整包检查的结论。
enum class PackageCheck {
  Ok,
  BadContainer,   // 打不开，或容器结构不对（魔数、长度字段）
  BadSignature,   // manifest 签名验证失败
  BadManifest,    // 签名正确但 manifest 内容不合规
  ImageMismatch,  // 镜像长度或哈希与 manifest 不符
};

// 完整检查一个 .fwpkg 文件：容器结构 → manifest 验签 → 解析 → 镜像长度 → 逐片哈希 → 整镜像哈希。
// 服务端导入固件、签发工具打包后自检都调用它。只有返回 Ok 时 manifest 才被写入。
PackageCheck verifyPackageFile(const QString& path, const ManifestVerifier& verifier,
                               Manifest* manifest, QString* error);

}  // namespace fwds
