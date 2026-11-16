// 明文开发信道：只用于 TLS 层完成之前联调网络层，以及网络层的单元测试。
// 两个程序只有在构建时打开 FWDS_DEV_PLAINTEXT 才会用到它；
// TLS 层合入后删除这个文件和对应的构建开关。
#pragma once

#include "common/net/channel_security.h"

namespace fwds {

class PlaintextDevChannel : public ChannelSecurity {
 public:
  bool encrypted() const override { return false; }
  void prepare(QSslSocket*, bool) override {}
  QString verifyPeer(const QSslSocket*, bool) override { return QString(); }
};

}  // namespace fwds
