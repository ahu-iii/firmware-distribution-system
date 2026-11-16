// ChannelSecurity：网络层和安全层之间的接口。
// 网络层只管连接、分帧、心跳、重连；信道怎么加密、对端证书怎么校验由安全层实现
// 这个接口后注入（TlsContext / CertVerifier，开发 1 的下一步）。
#pragma once

#include <QString>

class QSslSocket;

namespace fwds {

class ChannelSecurity {
 public:
  virtual ~ChannelSecurity() = default;

  // 是否走 TLS。为 true 时网络层发起 TLS 握手，握手成功后才开始收发 FWDS 帧。
  virtual bool encrypted() const = 0;

  // 握手之前配置 socket：协议版本、套件、本端证书与私钥、信任的 CA。
  virtual void prepare(QSslSocket* socket, bool serverSide) = 0;

  // 握手成功后的补充校验（对端名称、吊销状态、指纹，协议第 2 节）。
  // 通过返回空串；不通过返回原因，网络层会直接断开并记安全日志。
  virtual QString verifyPeer(const QSslSocket* socket, bool serverSide) = 0;
};

}  // namespace fwds
