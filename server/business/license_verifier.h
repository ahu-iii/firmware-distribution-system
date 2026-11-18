// LicenseVerifier：登录时的许可证检查（协议 5.1 节，错误码 2006）。
// 许可证 device.lic 由签发工具用 FSK 私钥签名，内容是设备 ID、硬件指纹哈希和有效期（设计第 15 节，
// 格式见 common/security/license.h）。LoginHandler 只依赖这个接口，单元测试可以换成假的实现。
#pragma once

#include <QByteArray>
#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

class LicenseVerifier {
 public:
  virtual ~LicenseVerifier() = default;

  // 检查 license（LOGIN 里 Base64 解码后的 device.lic 内容）是否是签给 deviceId 的有效许可证。
  // 通过返回空串，不通过返回原因（只写服务端日志）。
  virtual QString check(const QString& deviceId, const QByteArray& license) = 0;
};

// 正式的实现：用 FSK 公钥验签，核对设备 ID（= 对端证书名称）和有效期。
// 硬件指纹只有设备本机能核对，服务端不查。
class FskLicenseVerifier : public LicenseVerifier {
 public:
  // fsk 必须比本对象活得久（main 里的固件签名公钥验签器）
  explicit FskLicenseVerifier(const ManifestVerifier* fsk) : fsk_(fsk) {}

  QString check(const QString& deviceId, const QByteArray& license) override;

 private:
  const ManifestVerifier* fsk_;
};

}  // namespace fwds
