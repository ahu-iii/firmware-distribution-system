// AdminService：业务层的权限检查。对应测试报告 ST-12（绕过界面直接调业务接口也被拒）、
// ST-24 的开关部分（只有维护员能打开“允许下发”，默认关闭）。
#include <gtest/gtest.h>

#include "common/security/cert_verifier.h"
#include "tests/test_server_env.h"

using namespace fwds;
using fwds_test::pwd;
using fwds_test::ServerBackend;
using fwds_test::sharedPki;
using fwds_test::TestPki;

namespace {

// 建好三个角色的账号（都已改过初始口令），最后处于未登录状态。
struct RoleFixture : ServerBackend {
  RoleFixture() {
    loginAsMaintainer();
    QString error;
    EXPECT_TRUE(auth.createAccount(QStringLiteral("oper"), Role::Operator, pwd("Oper-pass-01"), false,
                                   &error));
    EXPECT_TRUE(auth.createAccount(QStringLiteral("audit"), Role::Auditor, pwd("Audit-pass-01"),
                                   false, &error));
    admin.logout();
  }
  void loginAs(const char* user, const char* password) {
    QString message;
    ASSERT_EQ(admin.login(QString::fromLatin1(user), pwd(password), &message), AuthResult::Ok)
        << message.toStdString();
  }
};

}  // namespace

TEST(AdminService, BootstrapOnlyWorksOnEmptyAccountTable) {
  ServerBackend be;
  QString error;
  EXPECT_TRUE(be.admin.needsBootstrap());
  ASSERT_TRUE(be.admin.bootstrapMaintainer(QStringLiteral("maint"), pwd("Maint-pass-01"), &error));
  EXPECT_FALSE(be.admin.needsBootstrap());
  // 已经有账号之后，不登录就再建一个维护员是不行的
  EXPECT_FALSE(be.admin.bootstrapMaintainer(QStringLiteral("evil"), pwd("Evil-pass-01"), &error));
  EXPECT_FALSE(be.auth.find(QStringLiteral("evil"), nullptr));
}

TEST(AdminService, NothingWorksWithoutLogin) {
  RoleFixture fx;
  QString error;
  QList<OperatorAccount> accounts;
  EXPECT_FALSE(fx.admin.registerDevice(sharedPki().dev001.certPem, QStringLiteral("PLC-X200"),
                                       QString(), &error));
  EXPECT_FALSE(fx.admin.setDispatchEnabled(true, &error));
  EXPECT_FALSE(fx.admin.listAccounts(&accounts, &error));
  EXPECT_FALSE(fx.admin.createAccount(QStringLiteral("eve"), Role::Maintainer, pwd("Eve-pass-0001"),
                                      &error));
  EXPECT_FALSE(fx.admin.can(Permission::ViewStatus));
  EXPECT_TRUE(fx.registry.devices().isEmpty());
  EXPECT_FALSE(fx.gate.enabled());
}

// ST-12：操作员、审计员直接调维护员专属的业务接口，全部被拒，数据没有变化
TEST(AdminService, OperatorAndAuditorCannotUseMaintainerFunctions) {
  RoleFixture fx;
  fx.loginAsMaintainer();
  fx.registerDevice(sharedPki().dev001);
  fx.admin.logout();

  const struct {
    const char* user;
    const char* password;
  } others[] = {{"oper", "Oper-pass-01"}, {"audit", "Audit-pass-01"}};
  for (const auto& who : others) {
    fx.loginAs(who.user, who.password);
    QString error;
    QList<OperatorAccount> accounts;
    EXPECT_FALSE(fx.admin.registerDevice(sharedPki().dev002.certPem, QStringLiteral("PLC-X200"),
                                         QString(), &error));
    EXPECT_FALSE(error.isEmpty());
    EXPECT_FALSE(fx.admin.setDeviceDisabled(QStringLiteral("DEV-001"), true, &error));
    EXPECT_FALSE(fx.admin.setDeviceGroup(QStringLiteral("DEV-001"), QStringLiteral("canary"), &error));
    EXPECT_FALSE(fx.admin.setDispatchEnabled(true, &error));
    EXPECT_FALSE(fx.admin.listAccounts(&accounts, &error));
    EXPECT_FALSE(fx.admin.createAccount(QStringLiteral("eve"), Role::Maintainer,
                                        pwd("Eve-pass-0001"), &error));
    EXPECT_FALSE(fx.admin.resetPassword(QStringLiteral("maint"), pwd("Hijack-pass-01"), &error));
    EXPECT_FALSE(fx.admin.unlockAccount(QStringLiteral("maint"), &error));
    EXPECT_FALSE(fx.admin.removeAccount(QStringLiteral("maint"), &error));
    EXPECT_TRUE(fx.admin.can(Permission::ViewStatus));  // 查看状态三个角色都可以
    EXPECT_FALSE(fx.admin.can(Permission::ManageDevices));
    fx.admin.logout();
  }

  // 什么都没被改动
  DeviceRecord d;
  ASSERT_TRUE(fx.registry.find(QStringLiteral("DEV-001"), &d));
  EXPECT_FALSE(d.disabled);
  EXPECT_TRUE(d.groupTag.isEmpty());
  EXPECT_EQ(fx.registry.devices().size(), 1);
  EXPECT_FALSE(fx.gate.enabled());
  EXPECT_FALSE(fx.auth.find(QStringLiteral("eve"), nullptr));
  QString message;
  EXPECT_EQ(fx.admin.login(QStringLiteral("maint"), pwd("Maint-pass-01"), &message), AuthResult::Ok);
}

// 检查项 7-1：“允许下发”默认关闭，只有维护员能开关
TEST(AdminService, DispatchSwitchDefaultsOffAndOnlyMaintainerCanToggle) {
  RoleFixture fx;
  EXPECT_FALSE(fx.gate.enabled());
  QList<bool> changes;
  QObject::connect(&fx.gate, &DispatchGate::changed, [&](bool on) { changes.append(on); });
  QString error;

  fx.loginAs("oper", "Oper-pass-01");
  EXPECT_FALSE(fx.admin.setDispatchEnabled(true, &error));
  EXPECT_FALSE(fx.gate.enabled());
  fx.admin.logout();

  fx.loginAsMaintainer();
  EXPECT_TRUE(fx.admin.setDispatchEnabled(true, &error));
  EXPECT_TRUE(fx.gate.enabled());
  fx.admin.logout();
  EXPECT_TRUE(fx.gate.enabled());  // 开关是服务端的状态，不随维护员退出而变

  fx.loginAs("oper", "Oper-pass-01");
  EXPECT_FALSE(fx.admin.setDispatchEnabled(false, &error));  // 操作员也不能关
  fx.admin.logout();
  fx.loginAsMaintainer();
  EXPECT_TRUE(fx.admin.setDispatchEnabled(false, &error));
  EXPECT_EQ(changes, (QList<bool>{true, false}));
}

// 设计 11.4 节：新建账号、被重置口令的账号，改口令之前什么都做不了
TEST(AdminService, NewAccountMustChangePasswordFirst) {
  ServerBackend be;
  be.loginAsMaintainer();
  QString error;
  ASSERT_TRUE(be.admin.createAccount(QStringLiteral("maint2"), Role::Maintainer,
                                     pwd("Initial-pass-01"), &error));
  be.admin.logout();

  ASSERT_EQ(be.admin.login(QStringLiteral("maint2"), pwd("Initial-pass-01"), &error), AuthResult::Ok);
  EXPECT_TRUE(be.admin.mustChangePassword());
  EXPECT_FALSE(be.admin.can(Permission::ManageDevices));
  EXPECT_FALSE(be.admin.setDispatchEnabled(true, &error));

  // 改口令：原口令要对、新口令要合规、不能和原来一样
  EXPECT_FALSE(be.admin.changeOwnPassword(pwd("Wrong-pass-00"), pwd("Changed-pass-02"), &error));
  EXPECT_FALSE(be.admin.changeOwnPassword(pwd("Initial-pass-01"), pwd("weak"), &error));
  EXPECT_FALSE(be.admin.changeOwnPassword(pwd("Initial-pass-01"), pwd("Initial-pass-01"), &error));
  ASSERT_TRUE(be.admin.changeOwnPassword(pwd("Initial-pass-01"), pwd("Changed-pass-02"), &error))
      << error.toStdString();
  EXPECT_FALSE(be.admin.mustChangePassword());
  EXPECT_TRUE(be.admin.setDispatchEnabled(true, &error));

  be.admin.logout();
  EXPECT_EQ(be.admin.login(QStringLiteral("maint2"), pwd("Initial-pass-01"), &error),
            AuthResult::BadCredentials);
  EXPECT_EQ(be.admin.login(QStringLiteral("maint2"), pwd("Changed-pass-02"), &error), AuthResult::Ok);
}

TEST(AdminService, AccountManagementByMaintainer) {
  RoleFixture fx;
  fx.loginAsMaintainer();
  QString error;
  QList<OperatorAccount> accounts;
  ASSERT_TRUE(fx.admin.listAccounts(&accounts, &error));
  EXPECT_EQ(accounts.size(), 3);

  // 重置别人的口令：对方下次登录必须改
  ASSERT_TRUE(fx.admin.resetPassword(QStringLiteral("oper"), pwd("Reset-pass-09"), &error));
  OperatorAccount oper;
  ASSERT_TRUE(fx.auth.find(QStringLiteral("oper"), &oper));
  EXPECT_TRUE(oper.mustChange);

  // 不能删自己（系统里始终至少有一个维护员）；能删别人
  EXPECT_FALSE(fx.admin.removeAccount(QStringLiteral("maint"), &error));
  EXPECT_FALSE(fx.admin.resetPassword(QStringLiteral("maint"), pwd("Reset-pass-09"), &error));
  EXPECT_TRUE(fx.admin.removeAccount(QStringLiteral("audit"), &error));
  EXPECT_FALSE(fx.admin.removeAccount(QStringLiteral("audit"), &error));  // 已经不存在
  EXPECT_EQ(fx.auth.countByRole(Role::Maintainer), 1);
}

// 登录锁定经 AdminService 也生效（ST-14），维护员可以解锁
TEST(AdminService, LoginLocksAndMaintainerUnlocks) {
  RoleFixture fx;
  QString message;
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(fx.admin.login(QStringLiteral("oper"), pwd("Wrong-pass-00"), &message),
              AuthResult::BadCredentials);
  }
  EXPECT_EQ(fx.admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &message), AuthResult::Locked);
  EXPECT_TRUE(message.contains(QStringLiteral("锁定")));
  EXPECT_FALSE(fx.admin.loggedIn());

  fx.loginAsMaintainer();
  QString error;
  ASSERT_TRUE(fx.admin.unlockAccount(QStringLiteral("oper"), &error));
  fx.admin.logout();
  EXPECT_EQ(fx.admin.login(QStringLiteral("oper"), pwd("Oper-pass-01"), &message), AuthResult::Ok);
}

// 注册设备时对导入的证书做完整校验：别的 CA 签的、已吊销的、服务端证书、乱写的内容都不能注册
TEST(AdminService, RegisterDeviceValidatesCertificate) {
  TestPki pki;
  const fwds_test::Identity good = pki.issue(CertType::Device, QStringLiteral("DEV-010"));
  const fwds_test::Identity revoked = pki.issue(CertType::Device, QStringLiteral("DEV-011"));
  const fwds_test::Identity serverCert = pki.issue(CertType::Server, QStringLiteral("127.0.0.1"));
  TestPki other(QStringLiteral("Other CA"));
  const fwds_test::Identity foreign = other.issue(CertType::Device, QStringLiteral("DEV-012"));

  CertVerifier verifier;
  QString error;
  ASSERT_TRUE(verifier.loadCa(pki.caPem(), &error));
  ASSERT_TRUE(verifier.loadCrl(pki.crl({revoked.serialHex}), &error));

  ServerBackend be;
  be.admin.setCertVerifier(&verifier);
  be.loginAsMaintainer();
  const QString model = QStringLiteral("PLC-X200");
  EXPECT_TRUE(be.admin.registerDevice(good.certPem, model, QString(), &error)) << error.toStdString();
  EXPECT_FALSE(be.admin.registerDevice(revoked.certPem, model, QString(), &error));
  EXPECT_FALSE(be.admin.registerDevice(foreign.certPem, model, QString(), &error));
  EXPECT_FALSE(be.admin.registerDevice(serverCert.certPem, model, QString(), &error));
  EXPECT_FALSE(be.admin.registerDevice("not a certificate", model, QString(), &error));
  // 型号必填；型号、分组里不允许奇怪的字符
  EXPECT_FALSE(be.admin.registerDevice(good.certPem, QString(), QString(), &error));
  EXPECT_FALSE(be.admin.registerDevice(good.certPem, QStringLiteral("x'; DROP TABLE device;--"),
                                       QString(), &error));
  EXPECT_FALSE(be.admin.setDeviceGroup(QStringLiteral("DEV-010"), QStringLiteral("a b\n"), &error));
  EXPECT_EQ(be.registry.devices().size(), 1);
}
