// 出厂写入：给一台全新的（模拟）设备装上第一份固件。
// 真实设备的出厂固件是在产线上烧进去的；这里对应 fwds-client --provision <固件包>：
// 把一个 .fwpkg 完整检查后写进分区 a，并建立 boot.json。之后的升级都走服务端推送。
#pragma once

#include <QString>

#include "common/security/manifest_verifier.h"

namespace fwds {

// 只对空设备有效：设备目录里已经有 boot.json 或任何一个分区里已有固件时拒绝，不覆盖现有固件。
// 固件包要通过和服务端导入时相同的整包检查（验签、逐片哈希、整镜像哈希），型号要和本设备一致，
// 写入后还要通过 Bootloader 的启动检查和自检。
bool provisionDevice(const QString& deviceDir, const QString& packagePath,
                     const ManifestVerifier& verifier, const QString& deviceModel, QString* error);

}  // namespace fwds
