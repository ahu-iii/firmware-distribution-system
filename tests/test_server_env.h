// 测试用的服务端“后台”：内存数据库 + 账号 + 设备注册表 + 管理入口 + 登录处理所需的部件。
// 设备一律走真实的注册流程（维护员登录 → AdminService::registerDevice），不绕过权限检查。
#pragma once

#include <gtest/gtest.h>
#include <memory>

#include "server/business/admin_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/login_throttle.h"
#include "server/security/operator_auth.h"
#include "server/storage/database.h"
#include "tests/test_pki.h"

namespace fwds_test {

// 测试里新建账号用的迭代次数：取允许的下限，让测试跑得快一些。
// 生产默认值 600 000 次由 OperatorAuth.DefaultIterationsMatchDesign 单独验证。
inline constexpr int kTestIterations = fwds::kPwdMinIterations;

inline fwds::SecureBuffer pwd(const char* text) {
  return fwds::passwordFromString(QString::fromUtf8(text));
}

struct ServerBackend {
  // dbPath 默认用内存数据库；要测“重启后数据还在”时传文件路径。
  explicit ServerBackend(const QString& dbPath = QStringLiteral(":memory:")) {
    QString error;
    EXPECT_TRUE(db.open(dbPath, &error)) << error.toStdString();
    EXPECT_TRUE(registry.load(&error)) << error.toStdString();
  }

  // 建一个维护员并登录（账号表已有账号时直接登录）。
  void loginAsMaintainer() {
    QString error;
    if (admin.needsBootstrap()) {
      ASSERT_TRUE(admin.bootstrapMaintainer(QStringLiteral("maint"), pwd("Maint-pass-01"), &error))
          << error.toStdString();
    }
    ASSERT_EQ(admin.login(QStringLiteral("maint"), pwd("Maint-pass-01"), &error),
              fwds::AuthResult::Ok)
        << error.toStdString();
  }

  // 以维护员身份注册一台设备。
  void registerDevice(const Identity& identity, const QString& group = QString()) {
    if (!admin.loggedIn()) loginAsMaintainer();
    QString error;
    ASSERT_TRUE(admin.registerDevice(identity.certPem, QStringLiteral("PLC-X200"), group, &error))
        << error.toStdString();
  }

  fwds::Database db;
  fwds::OperatorAuth auth{&db, kTestIterations};
  fwds::DeviceRegistry registry{&db};
  fwds::DispatchGate gate;
  fwds::AdminService admin{&auth, &registry, &gate};
  // 登录失败锁定：默认 5 次 / 5 分钟 / 10 分钟，与设计一致
  fwds::LoginThrottle throttle{5, 5 * 60 * 1000, 10 * 60 * 1000};
};

}  // namespace fwds_test
