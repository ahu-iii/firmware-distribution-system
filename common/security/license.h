// 设备许可证 device.lic（设计第 15 节“许可证文件绑定”，协议文档 7.3 节）。
// 内容是设备 ID、硬件指纹、签发时间和到期时间，由签发工具用 FSK 私钥签名。
//   设备端启动时检查：签名、设备 ID 等于配置的 device_id、硬件指纹等于本机、没有过期；
//     任何一项不符都拒绝运行，所以许可证拷到别的机器上用不了。
//   服务端在 LOGIN 时检查：签名、设备 ID 等于对端证书名称、没有过期（硬件指纹服务端无从核对）。
// 文件格式：{ "body": "<Base64, body JSON 的原始字节>", "sig": "<Base64, FSK 对 FWDS-LIC-1 ‖ body 的签名>" }。
// 和 manifest 一样先验签、后解析：签名验不过时 body 的 JSON 根本不会被解析。
#pragma once

#include <QByteArray>
#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

inline constexpr int kMaxLicenseFileSize = 8 * 1024;  // device.lic 不到 1 KB，超过 8 KB 的不读

struct License {
  QString deviceId;
  QString hwFingerprint;  // 本机硬件标识的 SHA-256，小写十六进制（localHardwareFingerprint）
  qint64 issuedAtMs = 0;  // UTC 毫秒
  qint64 expiresAtMs = 0;
};

// 签名覆盖的字节：用途前缀 "FWDS-LIC-1" 接 body 原始字节。
QByteArray licenseSignedMessage(const QByteArray& body);

// 签发工具用：把许可证内容编成 body JSON 的字节。
QByteArray encodeLicenseBody(const License& license);

// 签发工具用：body 和签名拼成 device.lic 文件内容。
QByteArray encodeLicenseFile(const QByteArray& body, const QByteArray& signature);

// 先验签、后解析。签名不对、格式不对都返回 false；不检查设备 ID、硬件指纹和有效期。
bool verifyLicense(const QByteArray& fileBytes, const ManifestVerifier& fsk, License* out,
                   QString* error);

// 检查许可证是否给了这台设备、在有效期内。hwFingerprint 为空时不比对硬件指纹（服务端用）。
bool checkLicense(const License& license, const QString& deviceId, const QString& hwFingerprint,
                  qint64 nowMs, QString* error);

// 本机的硬件指纹：SHA-256("FWDS-HW-1" ‖ 操作系统给出的机器唯一标识)，小写十六进制。
// 机器标识：Linux 是 /etc/machine-id，macOS 是 IOPlatformUUID，Windows 是注册表里的 MachineGuid
// （Qt 的 QSysInfo::machineUniqueId）。取不到时返回空串，调用方应拒绝运行。
QString localHardwareFingerprint();

// 设备端启动时的完整检查：读 path，验签，核对 deviceId、本机硬件指纹和有效期。
// 通过时 licenseBytes 里是文件内容（LOGIN 时原样发给服务端）。
bool loadDeviceLicense(const QString& path, const ManifestVerifier& fsk, const QString& deviceId,
                       QByteArray* licenseBytes, QString* error);

}  // namespace fwds
