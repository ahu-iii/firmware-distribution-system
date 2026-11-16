// 口令输入（设计 11.3 节）：CA 私钥的口令“使用时人工输入”，不存在任何文件里。
#pragma once

#include <QString>

#include "common/crypto/secure_buffer.h"

namespace fwds {

// 签发工具自己的两个口令环境变量（CA 私钥、固件签名密钥 FSK）。交互使用时都不用设，工具会在终端里提示输入；
// 部署脚本和自动化测试没有终端，才通过环境变量把口令传进来。
inline constexpr char kCaPassphraseEnv[] = "FWDS_CA_PASSPHRASE";
inline constexpr char kFskPassphraseEnv[] = "FWDS_FSK_PASSPHRASE";

// 取得一个口令：环境变量 envName 有值就用它（取走后清除），否则在终端提示输入，输入不回显。
// confirm 为 true 时要求输入两遍并比对（设置新口令时用）。
bool obtainPassphrase(const char* envName, const QString& prompt, bool confirm,
                      SecureBuffer* passphrase, QString* error);

}  // namespace fwds
