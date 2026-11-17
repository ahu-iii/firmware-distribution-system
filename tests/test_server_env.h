// 测试用的服务端“后台”：内存数据库 + 账号 + 设备注册表 + 固件库 + 管理入口 + 登录处理所需的部件。
// 设备注册和固件导入一律走真实的流程（维护员登录 → AdminService），不绕过权限检查。
#pragma once

#include <QTemporaryDir>
#include <gtest/gtest.h>
#include <memory>

#include "server/business/admin_service.h"
#include "server/business/device_registry.h"
#include "server/business/dispatch_gate.h"
#include "server/business/login_throttle.h"
#include "server/security/operator_auth.h"
#include "server/storage/database.h"
#include "tests/test_fsk.h"
#include "tests/test_pki.h"

namespace fwds_test {

// 测试里新建账号用的迭代次数：取允许的下限，让测试跑得快一些。
// 生产默认值 600 000 次由 OperatorAuth.DefaultIterationsMatchDesign 单独验证。
inline constexpr int kTestIterations = fwds::kPwdMinIterations;

inline fwds::SecureBuffer pwd(const char* text) {
  return fwds::passwordFromString(QString::fromUtf8(text));
}

struct ServerBackend {
  // dbPath 默认用内存数据库、固件库目录默认用一个临时目录；
  // 要测“重启后数据还在”时两个都传固定的路径。
  explicit ServerBackend(const QString& dbPath = QStringLiteral(":memory:"),
                         const QString& libraryPath = QString())
      : firmware(&db, fskVerifier, libraryPath.isEmpty() ? ownLibraryDir.path() : libraryPath) {
    QString error;
    EXPECT_TRUE(db.open(dbPath, &error)) << error.toStdString();
    EXPECT_TRUE(registry.load(&error)) << error.toStdString();
    EXPECT_TRUE(firmware.load(&error)) << error.toStdString();
    admin.setFirmwareRepo(&firmware);
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

  // 以维护员身份导入一个 .fwpkg，返回入库后的包。
  fwds::StoredPackage importFirmware(const QString& path) {
    if (!admin.loggedIn()) loginAsMaintainer();
    QString error;
    EXPECT_TRUE(admin.importFirmware(path, &error)) << error.toStdString();
    // 最新导入的排在最前面
    const QList<fwds::StoredPackage> all = firmware.packages();
    return all.isEmpty() ? fwds::StoredPackage() : all.first();
  }

  // 维护员打开“允许下发”，然后换成操作员登录（没有这个账号就先建一个）。
  void openGateAndLoginAsOperator() {
    loginAsMaintainer();
    QString error;
    ASSERT_TRUE(admin.setDispatchEnabled(true, &error)) << error.toStdString();
    if (!auth.find(QStringLiteral("oper"), nullptr)) {
      ASSERT_TRUE(auth.createAccount(QStringLiteral("oper"), fwds::Role::Operator,
                                     pwd("Oper-pass-01"), false, &error))
          << error.toStdString();
    }
    ASSERT_EQ(admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &error), fwds::AuthResult::Ok)
        << error.toStdString();
  }

  fwds::Database db;
  fwds::OperatorAuth auth{&db, kTestIterations};
  fwds::DeviceRegistry registry{&db};
  fwds::DispatchGate gate;
  fwds::AdminService admin{&auth, &registry, &gate};
  QTemporaryDir ownLibraryDir;
  fwds::ManifestVerifier fskVerifier = trustedVerifier();
  fwds::FirmwareRepo firmware;  // 初始化用到上面两个成员，必须排在它们后面
  // 登录失败锁定：默认 5 次 / 5 分钟 / 10 分钟，与设计一致
  fwds::LoginThrottle throttle{5, 5 * 60 * 1000, 10 * 60 * 1000};
};

}  // namespace fwds_test
