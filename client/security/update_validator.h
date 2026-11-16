// UpdateValidator：设备收到 UPDATE_NOTIFY 之后、开始下载之前的三项检查（设计 12.2 节）。
// 顺序固定：① FSK 公钥验 manifest 签名 → ② 型号一致 → ③ 防降级。
// 任何一项不过都不下载，返回对应的错误码，由升级状态机上报 ALERT / RESULT。
#pragma once

#include <QByteArray>
#include <QString>

#include "client/security/anti_rollback.h"
#include "common/protocol.h"
#include "common/security/manifest_verifier.h"

namespace fwds {

class UpdateValidator {
 public:
  // verifier 里已装好 FSK 公钥；deviceModel 是本设备的型号（配置 [client] model）。
  // 防降级没有“不检查”的选项，必须给出实现。两个引用指向的对象要比本对象活得久。
  UpdateValidator(const ManifestVerifier& verifier, const QString& deviceModel,
                  const AntiRollback& antiRollback);

  // 返回 Ok 时 manifest 可以用于下载；否则返回：
  //   3001 SIG_INVALID        签名验证失败
  //   3014 MANIFEST_INVALID   签名正确但内容不合规
  //   3002 MODEL_MISMATCH     不是给本型号的固件
  //   3003 ROLLBACK_ATTEMPT   降级
  // detail 是给本地日志看的说明。
  ErrorCode check(const QByteArray& manifestRaw, const QByteArray& signature, Manifest* manifest,
                  QString* detail) const;

 private:
  const ManifestVerifier& verifier_;
  QString deviceModel_;
  const AntiRollback& antiRollback_;
};

}  // namespace fwds
