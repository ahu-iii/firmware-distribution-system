// 固件打包与签名：sign-fw 子命令的实现（设计 12.1 节，协议文档第 7 节）。
// 输入一个固件镜像和几项元数据，输出 .fwpkg：manifest + FSK 签名 + 镜像。
// 只有离线签发工具用得到，所以放在 signer/，不编进服务端和客户端程序。
#pragma once

#include <QIODevice>
#include <QString>

#include "common/crypto/openssl_util.h"
#include "common/manifest.h"

namespace fwds {

// 操作人员在命令行上给出的固件元数据。
struct FirmwareInfo {
  QString deviceModel;      // 适用型号
  QString version;          // 版本号 “主.次.修订”
  int securityVersion = 0;  // 安全版本号：修了安全漏洞的版本要加 1，设备据此拒绝装回旧固件
  QString releaseNote;      // 发布说明
};

// 新的包 ID：RAND_bytes 取 16 字节随机数，按 UUID 第 4 版的格式写成小写字符串。
QString newPackageId();

// 顺序读完 image，按 64 KB 分片，算出每片哈希和整镜像哈希，填好 manifest 的全部字段。
// 每次只读一片，不把镜像整个放进内存。
bool buildManifest(QIODevice* image, const FirmwareInfo& info, Manifest* manifest, QString* error);

// sign-fw 的全过程：读镜像生成 manifest → 用 FSK 私钥签名 → 写出 .fwpkg。
// outPath 已存在时拒绝覆盖。成功时 manifest 返回签进包里的内容。
bool signFirmware(const QString& imagePath, const FirmwareInfo& info, EVP_PKEY* fskPrivateKey,
                  const QString& outPath, Manifest* manifest, QString* error);

}  // namespace fwds
