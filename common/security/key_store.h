// KeyStore：私钥口令的注入和私钥文件的读取（设计 11.3 节，检查项 1-3）。
// 口令不写在源码和配置文件里：安装脚本把它存在只有运行账户能取出的地方（Linux 权限 600 的文件、
// macOS 钥匙串、Windows DPAPI，见 deploy/README.md），启动器取出后放进环境变量，
// 程序启动时从环境变量取走并立刻从环境里删掉。
#pragma once

#include <QString>

#include "common/crypto/secure_buffer.h"

namespace fwds {

// 保存服务端 / 设备私钥口令的环境变量名。
inline constexpr char kKeyPassphraseEnv[] = "FWDS_KEY_PASSPHRASE";

// 从环境变量取出口令，然后清除该环境变量。变量不存在或为空时返回 false。
bool takePassphraseFromEnv(const char* name, SecureBuffer* passphrase);

// 读取封装过的私钥文件并用口令解开，得到 PKCS#8 DER 明文。
bool loadSealedKeyFile(const QString& path, const SecureBuffer& passphrase, SecureBuffer* pkcs8,
                       QString* error);

}  // namespace fwds
