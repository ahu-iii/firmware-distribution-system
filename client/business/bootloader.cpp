#include "client/business/bootloader.h"

#include <QFile>

#include "common/firmware_image.h"
#include "common/log.h"

namespace fwds {

namespace {

// 模拟的启动自检：真实固件会检查外设、存储、看门狗等，这里读镜像头（common/firmware_image.h）：
// 头里自报的型号、版本要和 manifest 一致，自检标志必须是 0。
// 调用时镜像已经通过整镜像哈希核对，头里的内容是签发方写的，没有被改过。
bool selfTest(QFile* image, const Manifest& manifest, QString* detail) {
  ImageHeader header;
  if (!image->seek(0) || !parseImageHeader(image->read(kImageHeaderSize), &header)) {
    *detail = QStringLiteral("自检失败：镜像头无法识别");
    return false;
  }
  if (header.model != manifest.deviceModel || header.version != manifest.version) {
    *detail = QStringLiteral("自检失败：镜像自报的型号或版本与 manifest 不一致");
    return false;
  }
  if (header.selfTestFails) {
    *detail = QStringLiteral("自检失败：固件报告自检不通过");
    return false;
  }
  return true;
}

}  // namespace

Bootloader::Bootloader(const QString& deviceDir, const ManifestVerifier& verifier,
                       const QString& deviceModel)
    : slots_(deviceDir), verifier_(verifier), deviceModel_(deviceModel) {}

BootResult Bootloader::boot() {
  BootResult result;
  BootConfig& config = result.config;
  const BootConfigLoad loaded = loadBootConfig(slots_.bootConfigPath(), &config);
  if (loaded == BootConfigLoad::Missing) {
    qCInfo(lcApp) << "no boot.json, first power-on";
  } else if (loaded == BootConfigLoad::Corrupt) {
    // 原子写保证了断电不会写坏它；内容不合规只能是被人改过。按第一次上电处理，并留下安全日志
    qCCritical(lcSecurity) << "boot.json is corrupt, using defaults";
  }

  // ---- 第一段：有待确认的新固件 ----
  if (!config.pending.isEmpty()) {
    // 先把“又试了一次”记到盘上再去验。这样即使新固件一启动就让设备死机、断电，
    // 次数也在涨，涨过上限就不再试它
    config.bootAttempts += 1;
    save(config);

    Manifest candidate;
    ErrorCode code = ErrorCode::Ok;
    QString detail;
    if (config.bootAttempts > kMaxBootAttempts) {
      code = ErrorCode::BootFailed;
      detail = QStringLiteral("新固件连续 %1 次没有启动成功").arg(kMaxBootAttempts);
    } else {
      code = checkSlot(config.pending, config.minSecurityVersion, true, &candidate, &detail);
    }

    if (code == ErrorCode::Ok) {
      // 转正。自检通过之后才提升 min_security_version：要是提前提升，
      // 回滚时旧固件的安全版本号就低于下限，反而启动不了了
      config.active = config.pending;
      config.pending.clear();
      config.bootAttempts = 0;
      config.minSecurityVersion = qMax(config.minSecurityVersion, candidate.securityVersion);
      save(config);
      qCInfo(lcApp).noquote() << "new firmware confirmed:" << candidate.version << "slot"
                              << config.active;
      result.outcome = BootResult::Outcome::Upgraded;
      result.hasFirmware = true;
      result.running = candidate;
      return result;
    }

    // 回滚：只改 boot.json，旧分区本来就没动过
    qCWarning(lcSecurity).noquote() << "new firmware rejected, rolling back:" << errorName(code)
                                    << detail;
    config.pending.clear();
    config.bootAttempts = 0;
    save(config);
    result.outcome = BootResult::Outcome::RolledBack;
    result.code = code;
    result.detail = detail;
  }

  // ---- 第二段：启动 active 分区；不行就试另一个 ----
  QString detail;
  if (checkSlot(config.active, config.minSecurityVersion, false, &result.running, &detail) ==
      ErrorCode::Ok) {
    result.hasFirmware = true;
  } else {
    qCCritical(lcSecurity).noquote() << "active slot" << config.active << "cannot boot:" << detail;
    const QString other = otherSlot(config.active);
    // 另一个分区没有刚刚被确认过，所以除了验签还要过自检；
    // 安全版本号低于下限的旧固件（checkSlot 里检查）同样不启动
    if (checkSlot(other, config.minSecurityVersion, true, &result.running, &detail) ==
        ErrorCode::Ok) {
      config.active = other;
      save(config);
      result.hasFirmware = true;
      qCWarning(lcSecurity) << "booting the other slot" << other;
    } else {
      qCCritical(lcSecurity).noquote() << "slot" << other << "cannot boot either:" << detail
                                       << "- recovery mode, waiting for the server";
    }
  }

  // 正在运行的固件的安全版本号不应高于下限；高于说明 boot.json 丢过或是新出厂的设备，补上
  if (result.hasFirmware && result.running.securityVersion > config.minSecurityVersion) {
    config.minSecurityVersion = result.running.securityVersion;
    save(config);
  }
  return result;
}

ErrorCode Bootloader::checkSlot(const QString& slot, int minSecurityVersion, bool runSelfTest,
                                Manifest* manifest, QString* detail) const {
  // ① 验 manifest 签名（先验签后解析，和下载前用的是同一个函数）
  QByteArray manifestRaw;
  QByteArray signature;
  if (!slots_.readManifest(slot, &manifestRaw, &signature)) {
    *detail = QStringLiteral("分区 %1 里没有 manifest 或签名").arg(slot);
    return ErrorCode::BootFailed;
  }
  Manifest found;
  if (verifier_.verify(manifestRaw, signature, &found, detail) != ManifestCheck::Ok) {
    return ErrorCode::BootFailed;
  }
  // ② 型号、③ 防降级：下载前已经查过一次，但 Bootloader 不依赖“之前查过”
  if (found.deviceModel != deviceModel_) {
    *detail = QStringLiteral("分区 %1 里是型号 %2 的固件").arg(slot, found.deviceModel);
    return ErrorCode::BootFailed;
  }
  if (found.securityVersion < minSecurityVersion) {
    *detail = QStringLiteral("分区 %1 的安全版本号 %2 低于本机最小值 %3")
                  .arg(slot)
                  .arg(found.securityVersion)
                  .arg(minSecurityVersion);
    return ErrorCode::BootFailed;
  }
  // ④ 整镜像：长度、每一片的哈希、整镜像哈希都要和签名保护的 manifest 一致
  QFile image(slots_.imagePath(slot));
  if (!image.open(QIODevice::ReadOnly) || image.size() != found.imageSize) {
    *detail = QStringLiteral("分区 %1 的镜像不存在或长度不符").arg(slot);
    return ErrorCode::BootFailed;
  }
  if (!verifyImage(&image, found, detail)) return ErrorCode::BootFailed;
  // ⑤ 启动自检
  if (runSelfTest && !selfTest(&image, found, detail)) return ErrorCode::SelftestFailed;

  *manifest = found;
  return ErrorCode::Ok;
}

void Bootloader::save(const BootConfig& config) const {
  QString error;
  if (!saveBootConfig(slots_.bootConfigPath(), config, &error)) {
    // 存不上（磁盘满、目录不可写）时照样继续启动：下次上电会按盘上的旧记录重走一遍，结论一样
    qCCritical(lcApp).noquote() << error;
  }
}

}  // namespace fwds
