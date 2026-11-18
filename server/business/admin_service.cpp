#include "server/business/admin_service.h"

#include <QFileInfo>

#include "common/crypto/x509_util.h"
#include "common/log.h"

namespace fwds {

namespace {

// 型号、分组这类自由文本：限制长度和字符，免得把奇怪的内容写进数据库和日志。
bool isValidTag(const QString& text, bool allowEmpty) {
  if (text.isEmpty()) return allowEmpty;
  if (text.size() > 32) return false;
  for (const QChar c : text) {
    const bool ok = (c >= QLatin1Char('a') && c <= QLatin1Char('z')) ||
                    (c >= QLatin1Char('A') && c <= QLatin1Char('Z')) ||
                    (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('_') ||
                    c == QLatin1Char('.') || c == QLatin1Char('-');
    if (!ok) return false;
  }
  return true;
}

// 操作名 → 审计日志分类（设计第 13 章）。
QString categoryOf(const char* action) {
  const QByteArray a(action);
  if (a == "login" || a == "logout" || a == "change_password" || a == "bootstrap") {
    return audit::kAuth;
  }
  if (a == "dispatch" || a.startsWith("release_")) return audit::kRollout;
  return audit::kAdmin;
}

}  // namespace

AdminService::AdminService(OperatorAuth* auth, DeviceRegistry* registry, DispatchGate* gate,
                           QObject* parent)
    : QObject(parent), auth_(auth), registry_(registry), gate_(gate) {}

void AdminService::audit(const char* action, const QString& target, bool ok,
                         const QString& detail) {
  const QString actor = loggedIn_ ? current_.username : QStringLiteral("-");
  const QString line = QStringLiteral("actor=%1 action=%2 target=%3 result=%4%5")
                           .arg(actor, QString::fromLatin1(action),
                                target.isEmpty() ? QStringLiteral("-") : target,
                                ok ? QStringLiteral("ok") : QStringLiteral("fail"),
                                detail.isEmpty() ? QString() : QStringLiteral(" detail=") + detail);
  if (ok) qCInfo(lcAudit).noquote() << line;
  else qCWarning(lcAudit).noquote() << line;
  if (audit_) {
    // 来源主机：服务端界面运行在哪台主机上，操作就是从哪台主机发出的
    audit_->append(categoryOf(action), ok ? QStringLiteral("INFO") : QStringLiteral("WARN"), actor,
                   AuditService::localSource(), QString(),
                   QStringLiteral("action=%1 target=%2 result=%3%4")
                       .arg(QString::fromLatin1(action),
                            target.isEmpty() ? QStringLiteral("-") : target,
                            ok ? QStringLiteral("ok") : QStringLiteral("fail"),
                            detail.isEmpty() ? QString() : QStringLiteral(" detail=") + detail));
  }
}

bool AdminService::confirmPassword(const SecureBuffer& password, const char* action,
                                   const QString& target, QString* error) {
  // 用当前账号自己的口令确认。输错同样计入失败次数，连续输错 5 次账号锁定并退出登录
  const QString username = current_.username;
  const AuthResult check = auth_->verify(username, password, nullptr);
  if (check == AuthResult::Ok) return true;
  *error = check == AuthResult::Locked ? QStringLiteral("账号已锁定，操作未执行")
                                       : QStringLiteral("口令不正确，操作未执行");
  audit(action, target, false, QStringLiteral("password confirmation failed"));
  if (check == AuthResult::Locked) logout();
  return false;
}

bool AdminService::authorize(Permission permission, const char* action, const QString& target,
                             QString* error) {
  if (!loggedIn_) {
    *error = QStringLiteral("尚未登录");
    audit(action, target, false, QStringLiteral("not logged in"));
    return false;
  }
  if (current_.mustChange) {
    *error = QStringLiteral("请先修改初始口令");
    audit(action, target, false, QStringLiteral("password change required"));
    return false;
  }
  if (!roleAllows(current_.role, permission)) {
    *error = QStringLiteral("当前角色（%1）没有这项权限").arg(roleDisplayName(current_.role));
    audit(action, target, false, QStringLiteral("permission denied, role=") + roleKey(current_.role));
    return false;
  }
  return true;
}

bool AdminService::can(Permission permission) const {
  return loggedIn_ && !current_.mustChange && roleAllows(current_.role, permission);
}

// ---------- 首次运行 ----------

bool AdminService::needsBootstrap() const { return auth_->isEmpty(); }

bool AdminService::bootstrapMaintainer(const QString& username, const SecureBuffer& password,
                                       QString* error) {
  // 只有账号表为空时才允许；之后新建账号必须由已登录的维护员来做
  if (!auth_->isEmpty()) {
    *error = QStringLiteral("已经有账号，不能再次初始化");
    audit("bootstrap", username, false, QStringLiteral("account table not empty"));
    return false;
  }
  const bool ok = auth_->createAccount(username, Role::Maintainer, password, false, error);
  audit("bootstrap", username, ok);
  return ok;
}

// ---------- 登录 ----------

AuthResult AdminService::login(const QString& username, const SecureBuffer& password,
                               QString* message) {
  logout();
  OperatorAccount account;
  const AuthResult result = auth_->verify(username, password, &account);
  switch (result) {
    case AuthResult::Ok:
      loggedIn_ = true;
      current_ = account;
      audit("login", username, true, QStringLiteral("role=") + roleKey(account.role));
      emit sessionChanged();
      break;
    case AuthResult::Locked:
      *message = QStringLiteral("账号已锁定，请在 %1 之后再试")
                     .arg(account.lockedUntil.toLocalTime().toString(QStringLiteral("HH:mm:ss")));
      audit("login", username, false, QStringLiteral("locked"));
      break;
    case AuthResult::BadCredentials:
      // 不告诉对方是账号不存在还是口令不对
      *message = QStringLiteral("账号或口令不正确");
      audit("login", username.left(32), false, QStringLiteral("bad credentials"));
      break;
  }
  return result;
}

void AdminService::logout() {
  if (!loggedIn_) return;
  audit("logout", current_.username, true);
  loggedIn_ = false;
  current_ = OperatorAccount();
  emit sessionChanged();
}

bool AdminService::changeOwnPassword(const SecureBuffer& oldPassword,
                                     const SecureBuffer& newPassword, QString* error) {
  if (!loggedIn_) {
    *error = QStringLiteral("尚未登录");
    return false;
  }
  const QString username = current_.username;
  // 改口令前重新验证旧口令：防止别人趁账号没退出时把口令改掉
  const AuthResult check = auth_->verify(username, oldPassword, nullptr);
  if (check != AuthResult::Ok) {
    *error = check == AuthResult::Locked ? QStringLiteral("账号已锁定") : QStringLiteral("原口令不正确");
    audit("change_password", username, false, QStringLiteral("old password rejected"));
    if (check == AuthResult::Locked) logout();
    return false;
  }
  if (samePassword(oldPassword, newPassword)) {
    *error = QStringLiteral("新口令不能与原口令相同");
    return false;
  }
  const bool ok = auth_->setPassword(username, newPassword, false, error);
  audit("change_password", username, ok);
  if (ok) {
    current_.mustChange = false;
    emit sessionChanged();
  }
  return ok;
}

// ---------- 设备管理 ----------

bool AdminService::registerDevice(const QByteArray& certPem, const QString& model,
                                  const QString& groupTag, QString* error) {
  if (!authorize(Permission::ManageDevices, "register_device", QString(), error)) return false;

  const X509Ptr cert = certFromPem(certPem);
  if (!cert) {
    *error = QStringLiteral("不是合法的 PEM 证书");
    audit("register_device", QString(), false, QStringLiteral("malformed certificate"));
    return false;
  }
  DeviceRecord record;
  record.deviceId = certCommonName(cert.get());
  record.model = model.trimmed();
  record.groupTag = groupTag.trimmed();
  record.certFingerprint = certFingerprintSha256(cert.get());
  record.certNotAfter = certNotAfter(cert.get());

  if (!isValidTag(record.model, false) || !isValidTag(record.groupTag, true)) {
    *error = QStringLiteral("型号必填，型号和分组只能用字母、数字、下划线、点、减号，最长 32 个字符");
    return false;
  }
  // 导入的证书要过和握手时同样的完整校验：别的 CA 签的、过期的、已吊销的、不是设备证书的都不能注册
  if (verifier_) {
    PeerIdentity identity;
    const CertCheck check =
        verifier_->verify(certToDer(cert.get()), PeerRole::Device, QString(), &identity);
    if (!check.ok()) {
      *error = QStringLiteral("证书校验不通过：%1").arg(check.detail);
      audit("register_device", record.deviceId.left(64), false, check.detail);
      return false;
    }
  }
  if (record.deviceId.isEmpty()) {
    *error = QStringLiteral("证书里没有设备 ID");
    return false;
  }

  const bool ok = registry_->addOrUpdateDevice(record, error);
  // 指纹不是秘密（证书本身是公开的），记下前 16 位方便事后核对注册的是哪张证书
  audit("register_device", record.deviceId, ok,
        QStringLiteral("model=%1 group=%2 fingerprint=%3…")
            .arg(record.model, record.groupTag, record.certFingerprint.left(16)));
  return ok;
}

bool AdminService::setDeviceDisabled(const QString& deviceId, bool disabled, QString* error) {
  const char* action = disabled ? "disable_device" : "enable_device";
  if (!authorize(Permission::ManageDevices, action, deviceId, error)) return false;
  const bool ok = registry_->setDisabled(deviceId, disabled, error);
  audit(action, deviceId, ok);
  return ok;
}

bool AdminService::setDeviceGroup(const QString& deviceId, const QString& groupTag,
                                  QString* error) {
  if (!authorize(Permission::ManageDevices, "set_device_group", deviceId, error)) return false;
  const QString tag = groupTag.trimmed();
  if (!isValidTag(tag, true)) {
    *error = QStringLiteral("分组只能用字母、数字、下划线、点、减号，最长 32 个字符");
    return false;
  }
  const bool ok = registry_->setGroup(deviceId, tag, error);
  audit("set_device_group", deviceId, ok, QStringLiteral("group=") + tag);
  return ok;
}

// ---------- 固件库 ----------

bool AdminService::importFirmware(const QString& path, QString* error) {
  // 日志里只记文件名，不记完整路径（路径里可能带着操作人员的用户名、目录结构）
  const QString fileName = QFileInfo(path).fileName().left(64);
  if (!authorize(Permission::ImportFirmware, "import_firmware", fileName, error)) return false;
  if (!firmware_) {
    *error = QStringLiteral("固件库不可用");
    return false;
  }
  StoredPackage package;
  const PackageCheck check = firmware_->import(path, current_.username, &package, error);
  if (check != PackageCheck::Ok) {
    audit("import_firmware", fileName, false, *error);
    return false;
  }
  // 哈希不是秘密，记下前 16 位方便事后核对入库的是哪一份镜像
  const Manifest& m = package.manifest;
  audit("import_firmware", m.pkgId, true,
        QStringLiteral("model=%1 version=%2 security_version=%3 sha256=%4…")
            .arg(m.deviceModel, m.version)
            .arg(m.securityVersion)
            .arg(QString::fromLatin1(m.imageSha256.toHex().left(16))));
  return true;
}

// ---------- 单台下发 ----------

bool AdminService::dispatchFirmware(const QString& pkgId, const QString& deviceId,
                                    const SecureBuffer& password, QString* error) {
  if (!authorize(Permission::ManageRelease, "dispatch", deviceId, error)) return false;
  if (!rollout_) {
    *error = QStringLiteral("发布模块不可用");
    return false;
  }
  if (!confirmPassword(password, "dispatch", deviceId, error)) return false;
  qint64 releaseId = 0;
  const bool ok = rollout_->dispatchToDevice(pkgId, deviceId, current_.username, &releaseId, error);
  audit("dispatch", deviceId, ok,
        ok ? QStringLiteral("release=%1 pkg=%2 confirmed=password").arg(releaseId).arg(pkgId)
           : QStringLiteral("pkg=%1 reason=%2").arg(pkgId.left(36), *error));
  return ok;
}

// ---------- 灰度发布 ----------

bool AdminService::createRelease(const QString& pkgId, const QStringList& canaryDevices,
                                 const QString& canaryGroup, int concurrency, qint64* releaseId,
                                 QString* error) {
  if (!authorize(Permission::ManageRelease, "release_create", pkgId.left(36), error)) return false;
  if (!rollout_) {
    *error = QStringLiteral("发布模块不可用");
    return false;
  }
  if (!isValidTag(canaryGroup, true)) {
    *error = QStringLiteral("分组名不合法");
    return false;
  }
  const bool ok = rollout_->createRelease(pkgId, canaryDevices, canaryGroup, concurrency,
                                          current_.username, releaseId, error);
  audit("release_create", ok ? QStringLiteral("#%1").arg(*releaseId) : pkgId.left(36), ok,
        ok ? QStringLiteral("pkg=%1 canary=%2 group=%3 concurrency=%4")
                 .arg(pkgId, canaryDevices.join(QLatin1Char(',')).left(200),
                      canaryGroup.isEmpty() ? QStringLiteral("-") : canaryGroup)
                 .arg(concurrency)
           : *error);
  return ok;
}

bool AdminService::releaseOperation(Permission permission, const char* action, qint64 releaseId,
                                    const SecureBuffer* password, QString* error,
                                    const std::function<bool(QString*)>& operation) {
  const QString target = QStringLiteral("#%1").arg(releaseId);
  if (!authorize(permission, action, target, error)) return false;
  if (!rollout_) {
    *error = QStringLiteral("发布模块不可用");
    return false;
  }
  if (password && !confirmPassword(*password, action, target, error)) return false;
  const bool ok = operation(error);
  // 确认方式也记下来：审计时能看出这一步是重新输过口令的
  audit(action, target, ok,
        ok ? (password ? QStringLiteral("confirmed=password") : QString()) : *error);
  return ok;
}

bool AdminService::startCanary(qint64 releaseId, const SecureBuffer& password, QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_start_canary", releaseId, &password,
                          error, [&](QString* e) {
                            return rollout_->startCanary(releaseId, current_.username, e);
                          });
}

bool AdminService::confirmFull(qint64 releaseId, const SecureBuffer& password, QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_confirm_full", releaseId, &password,
                          error, [&](QString* e) {
                            return rollout_->confirmFull(releaseId, current_.username, e);
                          });
}

bool AdminService::resumeRelease(qint64 releaseId, const SecureBuffer& password, QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_resume", releaseId, &password, error,
                          [&](QString* e) {
                            return rollout_->resume(releaseId, current_.username, e);
                          });
}

bool AdminService::pushHeldDevices(qint64 releaseId, const SecureBuffer& password,
                                   QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_push_held", releaseId, &password,
                          error, [&](QString* e) {
                            return rollout_->pushHeld(releaseId, current_.username, e);
                          });
}

bool AdminService::terminateRelease(qint64 releaseId, const SecureBuffer& password,
                                    QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_terminate", releaseId, &password,
                          error, [&](QString* e) {
                            return rollout_->abort(releaseId, current_.username, false, e);
                          });
}

bool AdminService::pauseRelease(qint64 releaseId, QString* error) {
  return releaseOperation(Permission::ManageRelease, "release_pause", releaseId, nullptr, error,
                          [&](QString* e) {
                            return rollout_->pause(releaseId, current_.username, e);
                          });
}

bool AdminService::emergencyStop(qint64 releaseId, QString* error) {
  return releaseOperation(Permission::EmergencyStop, "release_emergency_stop", releaseId, nullptr,
                          error, [&](QString* e) {
                            return rollout_->abort(releaseId, current_.username, true, e);
                          });
}

// ---------- 审计日志 ----------

bool AdminService::recentAudit(int limit, const QString& category, QList<AuditEntry>* entries,
                               QString* error) {
  // 查看成功不写审计日志（审计员每次刷新都会调用，记下来只会淹没真正的操作）；被拒照样记录
  if (!authorize(Permission::ViewAudit, "audit_view", QString(), error)) return false;
  if (!audit_) {
    *error = QStringLiteral("审计日志不可用");
    return false;
  }
  *entries = audit_->recent(limit, category);
  return true;
}

bool AdminService::verifyAudit(AuditCheck* check, QString* error) {
  if (!authorize(Permission::ViewAudit, "audit_verify", QString(), error)) return false;
  if (!audit_) {
    *error = QStringLiteral("审计日志不可用");
    return false;
  }
  *check = audit_->verify();
  // 校验本身也留痕：什么时候、谁校验过、结果如何
  audit("audit_verify", QString(), check->ok, check->detail.left(120));
  return true;
}

// ---------- “允许下发”开关 ----------

bool AdminService::setDispatchEnabled(bool enabled, QString* error) {
  const char* action = enabled ? "dispatch_on" : "dispatch_off";
  if (!authorize(Permission::ToggleDispatch, action, QString(), error)) return false;
  gate_->setEnabled(enabled);
  audit(action, QString(), true);
  return true;
}

// ---------- 账号管理 ----------

bool AdminService::listAccounts(QList<OperatorAccount>* accounts, QString* error) {
  if (!authorize(Permission::ManageAccounts, "list_accounts", QString(), error)) return false;
  *accounts = auth_->accounts();
  return true;
}

bool AdminService::createAccount(const QString& username, Role role,
                                 const SecureBuffer& initialPassword, QString* error) {
  if (!authorize(Permission::ManageAccounts, "create_account", username.left(32), error)) {
    return false;
  }
  const bool ok = auth_->createAccount(username, role, initialPassword, true, error);
  audit("create_account", username.left(32), ok, QStringLiteral("role=") + roleKey(role));
  return ok;
}

bool AdminService::resetPassword(const QString& username, const SecureBuffer& newPassword,
                                 QString* error) {
  if (!authorize(Permission::ManageAccounts, "reset_password", username, error)) return false;
  if (username == current_.username) {
    *error = QStringLiteral("自己的口令请用“修改口令”");
    return false;
  }
  const bool ok = auth_->setPassword(username, newPassword, true, error);
  audit("reset_password", username, ok);
  return ok;
}

bool AdminService::unlockAccount(const QString& username, QString* error) {
  if (!authorize(Permission::ManageAccounts, "unlock_account", username, error)) return false;
  const bool ok = auth_->unlock(username, error);
  audit("unlock_account", username, ok);
  return ok;
}

bool AdminService::removeAccount(const QString& username, QString* error) {
  if (!authorize(Permission::ManageAccounts, "remove_account", username, error)) return false;
  // 能执行到这里的一定是维护员；不允许删自己，所以系统里始终至少有一个维护员，不会把自己锁在外面
  if (username == current_.username) {
    *error = QStringLiteral("不能删除当前登录的账号");
    audit("remove_account", username, false, QStringLiteral("self"));
    return false;
  }
  const bool ok = auth_->removeAccount(username, error);
  audit("remove_account", username, ok);
  return ok;
}

}  // namespace fwds
