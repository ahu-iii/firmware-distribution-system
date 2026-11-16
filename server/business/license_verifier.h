// LicenseVerifier：登录时许可证检查的接入点（协议 5.1 节，错误码 2006）。
// 许可证 device.lic 由签发工具用 FSK 私钥签名，内容是设备 ID、硬件指纹哈希和有效期（设计第 15 节）。
// 验签要用 FSK 公钥，RSA-PSS 验签函数已在 common/crypto/rsa_pss；许可证的签发（issue-lic）和
// 这个接口的实现在后续步骤完成，届时在 main 里交给 LoginHandler。
// LoginHandler 没有拿到实现时不检查许可证，并在启动日志里说明。
#pragma once

#include <QByteArray>
#include <QString>

namespace fwds {

class LicenseVerifier {
 public:
  virtual ~LicenseVerifier() = default;

  // 检查 license（LOGIN 里 Base64 解码后的 device.lic 内容）是否是签给 deviceId 的有效许可证。
  // 通过返回空串，不通过返回原因（只写服务端日志）。
  virtual QString check(const QString& deviceId, const QByteArray& license) = 0;
};

}  // namespace fwds
