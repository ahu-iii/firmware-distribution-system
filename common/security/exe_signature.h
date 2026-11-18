// 程序数字签名与启动自校验（设计第 15 节“程序数字签名”，测试用例 ST-31）。
// 签发工具 sign-exe 对程序文件签名，签名写在程序旁边的 <程序文件名>.sig（384 字节，原始二进制）。
// 签名覆盖的字节是 "FWDS-EXE-1" ‖ SHA-256(整个程序文件)，用 FSK 私钥签（协议文档 7.3 节）。
// 程序启动时先装好（指纹已核对的）FSK 公钥，再把自己的程序文件从头到尾算一遍哈希并验签：
// 程序被改了一个字节，哈希就变，签名验不过，拒绝运行。
// 打包时 UPX 加壳在签名之前做，签名覆盖的是最终发出去的那个文件。
#pragma once

#include <QByteArray>
#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

// 程序文件对应的签名文件路径：在后面加 ".sig"（Windows 上是 fwds-client.exe.sig）。
QString exeSignaturePath(const QString& exePath);

// 签名覆盖的字节：用途前缀 "FWDS-EXE-1" 接程序文件的 SHA-256（32 字节）。
QByteArray exeSignedMessage(const QByteArray& fileSha256);

// 分块读文件算 SHA-256，不把整个文件读进内存。
bool sha256OfFile(const QString& path, QByteArray* digest, QString* error);

enum class ExeCheck {
  Ok,       // 签名文件存在且验签通过
  Missing,  // 没有签名文件
  Invalid,  // 有签名文件但验不过：程序或签名被改过，或不是这把 FSK 签的
};

// 校验 exePath 和它旁边的签名文件。
ExeCheck verifyExecutable(const QString& exePath, const ManifestVerifier& fsk, QString* error);

// 程序启动时调用：校验正在运行的这个程序文件。
// 返回 false 表示应当拒绝运行：签名不符（任何版本都拒绝），或发布版缺少签名文件。
// 开发版缺少签名文件只写一条警告并返回 true（每次编译程序都会变，开发时不强制签名）。
bool selfCheckExecutable(const ManifestVerifier& fsk, QString* error);

}  // namespace fwds
