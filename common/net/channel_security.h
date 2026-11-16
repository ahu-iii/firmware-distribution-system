// ChannelSecurity：网络层和安全层之间的接口。
// 网络层只管连接、分帧、心跳、重连；信道怎么加密、对端证书怎么校验由安全层实现
// 这个接口后注入（common/security/tls_channel）。接口里没有“不加密”的选项：
// 网络层总是先做 TLS 握手，握手和补充校验都通过之后才收发 FWDS 帧。
#pragma once

#include <QString>

class QSslSocket;

namespace fwds {

// 对端证书里的身份信息，补充校验通过后由安全层填写。
struct PeerIdentity {
  QString name;         // 证书持有者名称：设备证书是设备 ID，服务端证书是主机名或 IP
  QString serialHex;    // 证书序列号（十六进制），吊销按它查
  QString fingerprint;  // 证书 SHA-256 指纹（十六进制），设备注册表按它绑定
};

class ChannelSecurity {
 public:
  virtual ~ChannelSecurity() = default;

  // 握手之前配置 socket：协议版本、套件、本端证书与私钥、信任的 CA。
  virtual void prepare(QSslSocket* socket, bool serverSide) = 0;

  // 握手成功后的补充校验（对端名称、吊销状态，协议第 2 节）。
  // 通过返回空串并填写 peer；不通过返回原因，网络层会直接断开并记安全日志。
  virtual QString verifyPeer(const QSslSocket* socket, bool serverSide, PeerIdentity* peer) = 0;
};

}  // namespace fwds
