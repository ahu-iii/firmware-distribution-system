// 密码学随机数（设计 10.4 节）：只用 RAND_bytes，全项目禁止 rand()。
#pragma once

#include <QByteArray>

namespace fwds {

// 返回 size 字节随机数。RAND_bytes 失败说明系统随机源不可用，
// 这时继续运行只会产生可预测的 nonce 和密钥，所以直接终止程序。
QByteArray randomBytes(int size);

}  // namespace fwds
