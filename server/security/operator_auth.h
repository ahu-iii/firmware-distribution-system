// OperatorAuth：服务端账号的口令存储与校验、角色与权限（设计第 11 章，检查项 1-2、第 5 类）。
//   口令存储  PBKDF2-HMAC-SHA256，每个账号 16 字节随机盐、迭代 600 000 次、输出 32 字节；
//             数据库里只有 派生函数名 + 迭代次数 + 盐 + 派生结果，没有明文，也没有单次哈希
//   口令校验  用账号自己的盐和迭代次数重新派生，常数时间比较
//   失败锁定  连续输错 5 次锁定 10 分钟，计数和解锁时间存在数据库里，重启程序不会清零
//   角色权限  操作员 / 维护员 / 审计员三个角色，权限表见 roleAllows()
// 这个类只管“账号数据”，不关心当前是谁在操作；谁能调用哪些操作由 AdminService 把关。
#pragma once

#include <QDateTime>
#include <QList>
#include <QString>

#include "common/crypto/kdf.h"
#include "common/crypto/secure_buffer.h"
#include "server/storage/database.h"

namespace fwds {

enum class Role {
  Operator,    // 操作员：发布固件
  Maintainer,  // 维护员：设备、固件库、CRL、“允许下发”开关、账号
  Auditor,     // 审计员：审计日志
};

// 需要授权的功能，与设计 11.1 节权限表的行一一对应。
enum class Permission {
  ViewStatus,      // 查看设备与发布状态
  ManageRelease,   // 新建发布、开始灰度、确认全量、暂停、继续
  EmergencyStop,   // 紧急停止
  ManageDevices,   // 设备注册与停用
  ImportFirmware,  // 导入固件
  ImportCrl,       // 导入 CRL
  ToggleDispatch,  // “允许下发”开关
  ManageAccounts,  // 账号管理
  ViewAudit,       // 查看与导出审计日志、校验日志完整性
};

// 权限表（设计 11.1 节）：role 是否拥有 permission。
bool roleAllows(Role role, Permission permission);

QString roleKey(Role role);                      // 数据库里存的值：operator / maintainer / auditor
bool roleFromKey(const QString& key, Role* role);
QString roleDisplayName(Role role);              // 界面上显示的中文名

inline constexpr int kPwdHashSize = 32;            // 派生结果长度（字节）
inline constexpr int kPwdMinIterations = 100000;   // 账号表里迭代次数低于这个值的记录拒绝使用
inline constexpr int kPwdMaxFailures = 5;          // 连续输错几次后锁定
inline constexpr int kPwdLockMinutes = 10;         // 锁定时长
inline constexpr int kPwdMinLength = 10;           // 口令最短长度
inline constexpr int kPwdMaxLength = 128;

// 账号表里可以给界面看的字段（不含盐和派生结果）。
struct OperatorAccount {
  QString username;
  Role role = Role::Operator;
  int failedCount = 0;
  QDateTime lockedUntil;    // 无效时间表示没有被锁定
  bool mustChange = false;  // 下次登录必须先改口令（新建账号、被重置口令之后）
};

enum class AuthResult {
  Ok,
  BadCredentials,  // 账号不存在或口令不对，对外不区分
  Locked,          // 账号处于锁定期
};

// 把界面输入的口令转成 SecureBuffer（UTF-8），中间用到的临时副本用完即清零。
SecureBuffer passwordFromString(const QString& text);

// 两个口令是否相同（常数时间比较）。界面核对“再输一遍”时用。
bool samePassword(const SecureBuffer& a, const SecureBuffer& b);

// 账号名规则：3 ~ 32 个字符，只允许字母、数字、下划线、点、减号。
bool isValidUsername(const QString& username);

// 口令规则：10 ~ 128 字节，至少包含一个字母和一个数字。合格返回空串，否则返回原因。
QString checkPasswordPolicy(const SecureBuffer& password);

class OperatorAuth {
 public:
  // iterations 是新建账号、修改口令时使用的迭代次数；校验时用账号表里存的那个值。
  explicit OperatorAuth(Database* db, int iterations = kKdfDefaultIterations);

  // 账号表是否为空（首次运行时要先创建一个维护员）。
  bool isEmpty() const;

  bool createAccount(const QString& username, Role role, const SecureBuffer& password,
                     bool mustChange, QString* error);

  // 校验口令。now 可以由调用方指定，方便测试锁定到期。account 可以为空指针。
  AuthResult verify(const QString& username, const SecureBuffer& password,
                    OperatorAccount* account,
                    const QDateTime& now = QDateTime::currentDateTimeUtc());

  // 换口令（重新生成盐），同时清除失败计数和锁定。
  bool setPassword(const QString& username, const SecureBuffer& password, bool mustChange,
                   QString* error);

  bool removeAccount(const QString& username, QString* error);
  bool unlock(const QString& username, QString* error);

  bool find(const QString& username, OperatorAccount* account) const;
  QList<OperatorAccount> accounts() const;
  int countByRole(Role role) const;

 private:
  bool derive(const SecureBuffer& password, const QByteArray& salt, int iterations,
              SecureBuffer* hash) const;

  Database* db_;
  int iterations_;
};

}  // namespace fwds
