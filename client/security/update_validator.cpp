#include "client/security/update_validator.h"

namespace fwds {

UpdateValidator::UpdateValidator(const ManifestVerifier& verifier, const QString& deviceModel,
                                 const AntiRollback& antiRollback)
    : verifier_(verifier), deviceModel_(deviceModel), antiRollback_(antiRollback) {}

ErrorCode UpdateValidator::check(const QByteArray& manifestRaw, const QByteArray& signature,
                                 Manifest* manifest, QString* detail) const {
  // ① 验签。verified 是局部变量，三项检查全部通过之后才交给调用方
  Manifest verified;
  const ManifestCheck signatureCheck = verifier_.verify(manifestRaw, signature, &verified, detail);
  if (signatureCheck == ManifestCheck::BadSignature) return ErrorCode::SigInvalid;
  if (signatureCheck == ManifestCheck::BadContent) return ErrorCode::ManifestInvalid;

  // ② 型号。型号写在受签名保护的 manifest 里，攻击者没法把别的型号的固件改成本型号
  if (verified.deviceModel != deviceModel_) {
    *detail = QStringLiteral("固件适用型号 %1，本设备型号 %2").arg(verified.deviceModel, deviceModel_);
    return ErrorCode::ModelMismatch;
  }

  // ③ 防降级
  if (!antiRollback_.allows(verified, detail)) return ErrorCode::RollbackAttempt;

  *manifest = verified;
  return ErrorCode::Ok;
}

}  // namespace fwds
