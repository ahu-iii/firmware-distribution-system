// AdminService：服务端所有管理操作的唯一入口（设计 11.1 节“权限在界面和业务层各检查一次”）。
// 它记着“当前登录的是谁”，每个操作先用 authorize() 核对角色权限再执行：
//   - 界面按角色隐藏没有权限的入口（第一次检查）；
//   - 即使绕过界面直接调这里的函数，角色不符也会被拒绝并记录（第二次检查，用例 ST-12）。
// DeviceRegistry、DispatchGate、FirmwareRepo、RolloutManager 里改数据的函数是私有的，
// 只对本类开放，别处想绕也绕不过去。
// 每次操作（无论成功、失败还是被拒）都写一条审计日志：谁、从哪台主机、做什么、对象、结果。
// 审计日志进 AuditService 的哈希链（设计第 13 章），同时写一份 fwds.audit 进程日志。
// 会向设备推送固件的操作（下发、开始灰度、确认全量、继续、推送待确认设备）和终止发布，
// 执行前要求操作员重新输入自己的口令（二次确认，设计 4.2 节，用例 ST-23）；
// 暂停和紧急停止是让设备“少动”的安全动作，不要求口令，越快越好。
#pragma once

#include <QObject>
#include <functional>

#include "common/security/cert_verifier.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/firmware_repo.h"
#include "server/business/rollout_manager.h"
#include "server/security/audit_service.h"
#include "server/security/operator_auth.h"

namespace fwds {

class AdminService : public QObject {
  Q_OBJECT
 public:
  AdminService(OperatorAuth* auth, DeviceRegistry* registry, DispatchGate* gate,
               QObject* parent = nullptr);

  // 注册设备时用来校验导入的证书（签发链、有效期、吊销状态）。由 main 设置。
  void setCertVerifier(const CertVerifier* verifier) { verifier_ = verifier; }
  // 固件库和发布模块。由 main 设置；没有设置时对应的操作一律失败。
  void setFirmwareRepo(FirmwareRepo* firmware) { firmware_ = firmware; }
  void setRolloutManager(RolloutManager* rollout) { rollout_ = rollout; }
  // 审计日志。由 main 设置；没有设置时操作记录只写进程日志。
  void setAuditService(AuditService* audit) { audit_ = audit; }

  // ---- 首次运行：账号表为空时创建第一个维护员 ----
  bool needsBootstrap() const;
  bool bootstrapMaintainer(const QString& username, const SecureBuffer& password, QString* error);

  // ---- 登录、退出、改自己的口令 ----
  // 失败时 message 是可以直接显示给用户的提示。
  AuthResult login(const QString& username, const SecureBuffer& password, QString* message);
  void logout();
  bool loggedIn() const { return loggedIn_; }
  const OperatorAccount& current() const { return current_; }
  // 新建账号或被重置口令后，必须先改口令才能做别的操作（设计 11.4 节）。
  bool mustChangePassword() const { return loggedIn_ && current_.mustChange; }
  bool changeOwnPassword(const SecureBuffer& oldPassword, const SecureBuffer& newPassword,
                         QString* error);

  // 当前登录账号是否有某项权限。界面用它决定显示哪些入口。
  bool can(Permission permission) const;

  // ---- 设备管理（维护员）----
  // certPem 是签发工具生成的设备证书；设备 ID 取证书里的名称，指纹由证书算出，不手工输入。
  bool registerDevice(const QByteArray& certPem, const QString& model, const QString& groupTag,
                      QString* error);
  bool setDeviceDisabled(const QString& deviceId, bool disabled, QString* error);
  bool setDeviceGroup(const QString& deviceId, const QString& groupTag, QString* error);

  // ---- 固件库（维护员）----
  // 导入一个 .fwpkg：服务端整包检查（验签、逐片哈希、整镜像哈希）通过才入库。
  bool importFirmware(const QString& path, QString* error);

  // ---- 单台下发（操作员，二次确认）----
  // 把固件库里的一个包下发给一台在线设备。“允许下发”开关和互锁在 RolloutManager 里裁决。
  // password 是当前账号的口令，核对不过不执行。
  bool dispatchFirmware(const QString& pkgId, const QString& deviceId,
                        const SecureBuffer& password, QString* error);

  // ---- 灰度发布（设计 4.2 节）----
  // 新建发布（操作员）：只写草稿，不推送。canaryGroup 是按分组选金丝雀时的分组名，手动勾选时为空。
  bool createRelease(const QString& pkgId, const QStringList& canaryDevices,
                     const QString& canaryGroup, int concurrency, qint64* releaseId,
                     QString* error);
  // 以下五个操作员操作都要二次确认（password 为当前账号的口令）
  bool startCanary(qint64 releaseId, const SecureBuffer& password, QString* error);
  bool confirmFull(qint64 releaseId, const SecureBuffer& password, QString* error);
  bool resumeRelease(qint64 releaseId, const SecureBuffer& password, QString* error);
  bool pushHeldDevices(qint64 releaseId, const SecureBuffer& password, QString* error);
  bool terminateRelease(qint64 releaseId, const SecureBuffer& password, QString* error);
  // 暂停（操作员）、紧急停止（操作员、维护员）：不要求口令
  bool pauseRelease(qint64 releaseId, QString* error);
  bool emergencyStop(qint64 releaseId, QString* error);

  // ---- 审计日志（审计员）----
  bool searchAudit(const AuditFilter& filter, AuditSearchResult* result, QString* error);
  bool verifyAudit(AuditCheck* check, QString* error);

  // ---- “允许下发”开关（维护员）----
  bool setDispatchEnabled(bool enabled, QString* error);

  // ---- 账号管理（维护员）----
  bool listAccounts(QList<OperatorAccount>* accounts, QString* error);
  // 新建的账号和被重置的账号，下次登录都必须先改口令。
  bool createAccount(const QString& username, Role role, const SecureBuffer& initialPassword,
                     QString* error);
  bool resetPassword(const QString& username, const SecureBuffer& newPassword, QString* error);
  bool unlockAccount(const QString& username, QString* error);
  bool removeAccount(const QString& username, QString* error);

 signals:
  // 登录、退出、改完口令之后发出，界面据此刷新可用功能。
  void sessionChanged();

 private:
  // 权限检查。不通过时填写 error、写日志并返回 false。action 是写进日志的操作名。
  bool authorize(Permission permission, const char* action, const QString& target, QString* error);
  // 二次确认：核对当前账号的口令。不对时填写 error、写日志并返回 false；连续输错会锁定账号并退出登录。
  bool confirmPassword(const SecureBuffer& password, const char* action, const QString& target,
                       QString* error);
  // 发布操作的公共部分：查权限 → 核对口令（password 为空指针时不核对）→ 执行 → 写审计日志。
  bool releaseOperation(Permission permission, const char* action, qint64 releaseId,
                        const SecureBuffer* password, QString* error,
                        const std::function<bool(QString*)>& operation);
  // 写一条操作记录。
  void audit(const char* action, const QString& target, bool ok, const QString& detail = QString());

  OperatorAuth* auth_;
  DeviceRegistry* registry_;
  DispatchGate* gate_;
  const CertVerifier* verifier_ = nullptr;
  FirmwareRepo* firmware_ = nullptr;
  RolloutManager* rollout_ = nullptr;
  AuditService* audit_ = nullptr;
  bool loggedIn_ = false;
  OperatorAccount current_;
};

}  // namespace fwds
