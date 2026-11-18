// 灰度发布的联调（设计 4.2 节）：真实 TLS、真实服务端与三台模拟设备（DEV-001 ~ DEV-003，同型号）。
// 覆盖的用例：
//   FT-11 灰度正常推进        FT-12 金丝雀失败自动暂停    ST-23 二次确认与留痕
//   ST-25 互锁冲突注入        ST-26 紧急停止              ST-27 断网不盲发
// 另外：“允许下发”被关闭、安全告警、全量失败比例超阈值时自动暂停；手动暂停与继续；角色。
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "tests/test_live.h"
#include "tests/test_util.h"

using namespace fwds;
using namespace fwds_test;

namespace {

const QString kDev1 = QStringLiteral("DEV-001");
const QString kDev2 = QStringLiteral("DEV-002");
const QString kDev3 = QStringLiteral("DEV-003");

class Rollout : public ::testing::Test {
 protected:
  // DEV-001 在分组 canary 里，另外两台没有分组
  Rollout() {
    backend.registerDevice(sharedPki().dev001, QStringLiteral("canary"));
    backend.registerDevice(sharedPki().dev002);
    backend.registerDevice(sharedPki().dev003);
  }

  // 做一个固件包并以维护员身份导入固件库，返回包 ID。chunks 是镜像的分片数。
  QString importFirmware(const QString& version, int securityVersion, bool selfTestFails = false,
                         int chunks = 5) {
    const DeviceFirmware fw(version, securityVersion, chunks * kChunkSize + 77, selfTestFails);
    Manifest manifest;
    const QString path = packageFileFor(fw, dir.path(), QStringLiteral("fw-") + version, &manifest);
    backend.importFirmware(path);
    return manifest.pkgId;
  }

  // 启动一台设备，它的升级结果交给服务端的发布模块（代替事件上报）。
  std::unique_ptr<LiveDevice> startDevice(LiveServer& fx, const Identity& identity,
                                          const QString& id, const QString& pkgId) {
    auto dev = std::make_unique<LiveDevice>(fx.port(), identity, id, dir.filePath(id));
    dev->reportResultsTo(fx.rollout.get(), pkgId);
    return dev;
  }

  // 设备已登录，并且至少上报过一次心跳。
  bool ready(const QString& deviceId) {
    return waitFor([&]() {
      DeviceRecord record;
      return backend.registry.find(deviceId, &record) && record.online &&
             !record.upgradeState.isEmpty();
    });
  }

  ReleaseInfo info(LiveServer& fx, qint64 id) {
    for (const ReleaseInfo& r : fx.rollout->releases(100)) {
      if (r.releaseId == id) return r;
    }
    return ReleaseInfo();
  }
  QString state(LiveServer& fx, qint64 id) { return info(fx, id).state; }
  bool waitState(LiveServer& fx, qint64 id, const QString& expected, int timeoutMs = 15000) {
    return waitFor([&]() { return state(fx, id) == expected; }, timeoutMs);
  }
  TargetInfo target(LiveServer& fx, qint64 id, const QString& deviceId) {
    for (const TargetInfo& t : fx.rollout->targets(id)) {
      if (t.deviceId == deviceId) return t;
    }
    return TargetInfo();
  }

  // 以操作员身份新建一个发布（草稿），返回发布号。
  qint64 create(const QString& pkgId, const QStringList& canary, int concurrency = 5,
                const QString& group = QString()) {
    qint64 id = 0;
    EXPECT_TRUE(backend.admin.createRelease(pkgId, canary, group, concurrency, &id, &error))
        << error.toStdString();
    return id;
  }

  // 审计日志里有没有包含这段文字的记录。
  bool audited(const QString& text) {
    for (const AuditEntry& e : backend.audit.recent(500)) {
      if (e.message.contains(text)) return true;
    }
    return false;
  }

  SecureBuffer operPwd() { return pwd("Oper-pass-01"); }

  QTemporaryDir dir;
  ServerBackend backend;
  QString error;
};

}  // namespace

// FT-11：金丝雀 DEV-001 先升级，其余设备不动；成功并观察期满后进入“待确认全量”；
// 操作员确认后 DEV-002、DEV-003 升级，发布完成。每一步都在审计日志里，推送类操作记着“重新输过口令”
TEST_F(Rollout, CanaryThenFullRollout) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  auto d2 = startDevice(fx, sharedPki().dev002, kDev2, pkg);
  auto d3 = startDevice(fx, sharedPki().dev003, kDev3, pkg);
  ASSERT_TRUE(ready(kDev1) && ready(kDev2) && ready(kDev3));
  backend.openGateAndLoginAsOperator();

  // 按分组选金丝雀：只有 DEV-001；其余两台进全量批
  const qint64 id = create(pkg, {kDev1}, 5, QStringLiteral("canary"));
  ReleaseInfo r = info(fx, id);
  EXPECT_EQ(r.state, QStringLiteral("draft"));
  EXPECT_EQ(r.total, 3);
  EXPECT_EQ(r.canary, 1);
  EXPECT_EQ(r.canaryGroup, QStringLiteral("canary"));

  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return d1->updater->state() == Updater::State::Success; }, 15000));
  // 金丝雀成功 → 观察期 → 待确认全量；这期间其余设备什么都没收到
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("awaiting_full")));
  EXPECT_EQ(d2->updater->state(), Updater::State::Idle);
  EXPECT_EQ(d3->updater->state(), Updater::State::Idle);
  EXPECT_EQ(target(fx, id, kDev2).status, QStringLiteral("pending"));

  ASSERT_TRUE(backend.admin.confirmFull(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("done"), 20000));
  EXPECT_EQ(d2->runningVersion(), QStringLiteral("2.1.0"));
  EXPECT_EQ(d3->runningVersion(), QStringLiteral("2.1.0"));
  r = info(fx, id);
  EXPECT_EQ(r.success, 3);
  EXPECT_EQ(target(fx, id, kDev3).progress, 100);

  // ST-23 留痕：操作者、来源主机、确认方式；自动推进也有记录
  EXPECT_TRUE(audited(QStringLiteral("action=release_start_canary target=#%1 result=ok detail=confirmed=password").arg(id)));
  EXPECT_TRUE(audited(QStringLiteral("action=release_confirm_full target=#%1 result=ok detail=confirmed=password").arg(id)));
  EXPECT_TRUE(audited(QStringLiteral("发布 #%1：观察期内无失败、无告警，待确认全量").arg(id)));
  // 操作员的操作记着来源主机（服务端界面所在的主机），设备上报的结果记着设备的地址
  for (const AuditEntry& e : backend.audit.recent(500, audit::kRollout)) {
    if (e.actor == QStringLiteral("oper")) EXPECT_EQ(e.source, AuditService::localSource());
    if (e.actor == kDev2) EXPECT_EQ(e.source, QStringLiteral("127.0.0.1"));
  }
  EXPECT_TRUE(backend.audit.verify().ok);
}

// FT-12：金丝雀装的是自检必定失败的固件 → DEV-001 回滚，发布自动暂停，DEV-002 不推送；
// 未通过灰度的发布不能继续，只能终止，终止后还没推的设备记为已取消
TEST_F(Rollout, CanaryFailurePausesRelease) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5, true);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  auto d2 = startDevice(fx, sharedPki().dev002, kDev2, pkg);
  ASSERT_TRUE(ready(kDev1) && ready(kDev2));
  backend.openGateAndLoginAsOperator();

  const qint64 id = create(pkg, {kDev1});
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitFor([&]() { return d1->updater->state() == Updater::State::RolledBack; }, 15000));
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("paused")));
  EXPECT_TRUE(info(fx, id).note.contains(QStringLiteral("金丝雀"))) << info(fx, id).note.toStdString();
  EXPECT_EQ(target(fx, id, kDev1).status, QStringLiteral("rolled_back"));
  EXPECT_EQ(d1->runningVersion(), QStringLiteral("2.0.0"));
  spin(300);
  EXPECT_EQ(d2->updater->state(), Updater::State::Idle);
  EXPECT_EQ(target(fx, id, kDev2).status, QStringLiteral("pending"));

  EXPECT_FALSE(backend.admin.resumeRelease(id, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("未通过灰度"))) << error.toStdString();
  ASSERT_TRUE(backend.admin.terminateRelease(id, operPwd(), &error)) << error.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("aborted"));
  EXPECT_EQ(target(fx, id, kDev2).status, QStringLiteral("cancelled"));
}

// ST-25：三种冲突全部被服务端拒绝并记录
//   ① 同一型号同时开始两个发布（单台下发也算一个发布）
//   ② 对升级中的设备再次推送（另见 Dispatch.BusyDeviceIsNotDispatchedAgain）
//   ③ 跳过灰度直接全量
TEST_F(Rollout, InterlocksRejectConflicts) {
  LiveServer fx(&backend);
  const QString pkgA = importFirmware(QStringLiteral("2.1.0"), 5, false, 30);
  const QString pkgB = importFirmware(QStringLiteral("2.2.0"), 6);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkgA);
  auto d2 = startDevice(fx, sharedPki().dev002, kDev2, pkgA);
  ASSERT_TRUE(ready(kDev1) && ready(kDev2));
  backend.openGateAndLoginAsOperator();

  const qint64 a = create(pkgA, {kDev1});
  const qint64 b = create(pkgB, {kDev2});  // 草稿可以有多个，不推送

  // ③ 草稿直接确认全量
  EXPECT_FALSE(backend.admin.confirmFull(a, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("还没有通过灰度"))) << error.toStdString();

  // ① A 开始灰度后，同型号的 B 不能开始，也不能另外单台下发
  ASSERT_TRUE(backend.admin.startCanary(a, operPwd(), &error)) << error.toStdString();
  EXPECT_FALSE(backend.admin.startCanary(b, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("同一型号"))) << error.toStdString();
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgB, kDev2, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("同一型号"))) << error.toStdString();
  EXPECT_EQ(state(fx, b), QStringLiteral("draft"));

  // ② DEV-001 正在升级 A 时再向它推 B：同样被拒
  EXPECT_FALSE(backend.admin.dispatchFirmware(pkgB, kDev1, operPwd(), &error));

  // 被拒的操作都有记录
  EXPECT_TRUE(audited(QStringLiteral("action=release_confirm_full target=#%1 result=fail").arg(a)));
  EXPECT_TRUE(audited(QStringLiteral("action=release_start_canary target=#%1 result=fail").arg(b)));
  EXPECT_TRUE(audited(QStringLiteral("action=dispatch target=DEV-002 result=fail")));
  spin(200);
  EXPECT_EQ(d2->updater->state(), Updater::State::Idle);
}

// ST-23：二次确认时输错口令，操作不执行，发布仍是草稿，设备什么都收不到，审计日志记下这次失败
TEST_F(Rollout, WrongPasswordDoesNothing) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  ASSERT_TRUE(ready(kDev1));
  backend.openGateAndLoginAsOperator();

  const qint64 id = create(pkg, {kDev1});
  EXPECT_FALSE(backend.admin.startCanary(id, pwd("Wrong-pass-01"), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("口令"))) << error.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("draft"));
  spin(200);
  EXPECT_EQ(d1->updater->state(), Updater::State::Idle);
  EXPECT_TRUE(audited(QStringLiteral("action=release_start_canary target=#%1 result=fail detail=password confirmation failed").arg(id)));
  // 输对之后照常执行
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
}

// ST-26：两台金丝雀正在下载时紧急停止（维护员也能按，审计员不能）→ 设备收到 UPDATE_CANCEL，
// 放弃升级、保留旧固件并上报 FAILED 3012；发布已终止，全量批的 DEV-003 不再推送
TEST_F(Rollout, EmergencyStopCancelsDevices) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5, false, 200);  // 大一点，下载要一会儿
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  auto d2 = startDevice(fx, sharedPki().dev002, kDev2, pkg);
  auto d3 = startDevice(fx, sharedPki().dev003, kDev3, pkg);
  ASSERT_TRUE(ready(kDev1) && ready(kDev2) && ready(kDev3));
  ASSERT_TRUE(backend.auth.createAccount(QStringLiteral("auditor"), Role::Auditor,
                                         pwd("Audit-pass-01"), false, &error));
  backend.openGateAndLoginAsOperator();

  const qint64 id = create(pkg, {kDev1, kDev2});
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  backend.loginAsMaintainer();  // 紧急停止由维护员来按
  ASSERT_TRUE(waitFor([&]() {
    return d1->updater->state() == Updater::State::Downloading &&
           d2->updater->state() == Updater::State::Downloading;
  }));
  ASSERT_TRUE(backend.admin.emergencyStop(id, &error)) << error.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("aborted"));
  EXPECT_EQ(target(fx, id, kDev3).status, QStringLiteral("cancelled"));

  ASSERT_TRUE(waitFor([&]() {
    return d1->updater->state() == Updater::State::Failed &&
           d2->updater->state() == Updater::State::Failed;
  }, 5000));
  EXPECT_EQ(d1->runningVersion(), QStringLiteral("2.0.0"));
  EXPECT_EQ(d2->runningVersion(), QStringLiteral("2.0.0"));
  ASSERT_TRUE(waitFor([&]() { return target(fx, id, kDev1).status == QStringLiteral("failed"); }));
  EXPECT_TRUE(target(fx, id, kDev1).lastError.startsWith(QStringLiteral("3012"))) << target(fx, id, kDev1).lastError.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("aborted"));  // 结果回来也不会改变已终止的发布
  spin(200);
  EXPECT_EQ(d3->updater->state(), Updater::State::Idle);
  EXPECT_TRUE(audited(QStringLiteral("action=release_emergency_stop target=#%1 result=ok").arg(id)));
  // 审计员没有紧急停止的权限
  ASSERT_EQ(backend.admin.login(QStringLiteral("auditor"), pwd("Audit-pass-01"), &error), AuthResult::Ok);
  EXPECT_FALSE(backend.admin.emergencyStop(id, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("没有这项权限"))) << error.toStdString();
}

// ST-27：全量阶段 DEV-002 离线 → 记为“待确认”，上线后不自动推送；操作员确认（输口令）后才升级
TEST_F(Rollout, OfflineDeviceIsHeldUntilConfirmed) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  auto d3 = startDevice(fx, sharedPki().dev003, kDev3, pkg);
  ASSERT_TRUE(ready(kDev1) && ready(kDev3));
  backend.openGateAndLoginAsOperator();

  const qint64 id = create(pkg, {kDev1});
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("awaiting_full")));
  ASSERT_TRUE(backend.admin.confirmFull(id, operPwd(), &error)) << error.toStdString();
  EXPECT_EQ(target(fx, id, kDev2).status, QStringLiteral("held"));
  EXPECT_TRUE(target(fx, id, kDev2).lastError.contains(QStringLiteral("不在线")));
  ASSERT_TRUE(waitFor([&]() { return target(fx, id, kDev3).status == QStringLiteral("success"); }, 15000));
  EXPECT_EQ(state(fx, id), QStringLiteral("full"));  // 还有待确认的设备，发布没有结束

  // DEV-002 上线：不自动推送
  auto d2 = startDevice(fx, sharedPki().dev002, kDev2, pkg);
  ASSERT_TRUE(ready(kDev2));
  spin(400);
  EXPECT_EQ(d2->updater->state(), Updater::State::Idle);
  EXPECT_EQ(target(fx, id, kDev2).status, QStringLiteral("held"));

  // 操作员确认后才推送
  ASSERT_TRUE(backend.admin.pushHeldDevices(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("done"), 15000));
  EXPECT_EQ(d2->runningVersion(), QStringLiteral("2.1.0"));
}

// “允许下发”在灰度途中被关闭 → 正在推送的发布自动暂停；重新打开后要操作员确认才继续
TEST_F(Rollout, ClosingGatePausesRelease) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5, false, 30);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  ASSERT_TRUE(ready(kDev1));
  backend.openGateAndLoginAsOperator();
  const qint64 id = create(pkg, {kDev1});
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();

  backend.loginAsMaintainer();
  ASSERT_TRUE(backend.admin.setDispatchEnabled(false, &error));
  EXPECT_EQ(state(fx, id), QStringLiteral("paused"));
  EXPECT_TRUE(info(fx, id).note.contains(QStringLiteral("允许下发")));

  // 开关关着时操作员不能继续
  ASSERT_EQ(backend.admin.login(QStringLiteral("oper"), operPwd(), &error), AuthResult::Ok);
  EXPECT_FALSE(backend.admin.resumeRelease(id, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("允许下发"))) << error.toStdString();
}

// 设备安全告警 → 还有设备没推的发布立即暂停
TEST_F(Rollout, SecurityAlertPausesRelease) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  ASSERT_TRUE(ready(kDev1));
  backend.openGateAndLoginAsOperator();
  const qint64 id = create(pkg, {kDev1});  // DEV-002、DEV-003 离线，在全量批里
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();

  fx.rollout->onDeviceAlert(kDev1, pkg, 3004, QStringLiteral("chunk hash mismatch"));
  EXPECT_EQ(state(fx, id), QStringLiteral("paused"));
  EXPECT_TRUE(info(fx, id).note.contains(QStringLiteral("3004")));
  EXPECT_TRUE(audited(QStringLiteral("发布 #%1 自动暂停").arg(id)));
}

// 全量阶段失败台数超过阈值（默认 20%）→ 自动暂停，还在排队的设备不再推送
TEST_F(Rollout, FullPhaseFailureRateAutoPauses) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5, false, 30);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  auto d2 = std::make_unique<LiveDevice>(fx.port(), sharedPki().dev002, kDev2, dir.filePath(kDev2));
  auto d3 = startDevice(fx, sharedPki().dev003, kDev3, pkg);
  ASSERT_TRUE(ready(kDev1) && ready(kDev2) && ready(kDev3));
  backend.openGateAndLoginAsOperator();

  const qint64 id = create(pkg, {kDev1}, 1);  // 一次只推一台
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("awaiting_full")));
  ASSERT_TRUE(backend.admin.confirmFull(id, operPwd(), &error)) << error.toStdString();
  ASSERT_EQ(target(fx, id, kDev2).status, QStringLiteral("notified"));
  ASSERT_EQ(target(fx, id, kDev3).status, QStringLiteral("pending"));

  // DEV-002 报告写入失败：全量批 1 / 2 台失败，超过 20%
  fx.rollout->onDeviceResult(kDev2, id, pkg, QStringLiteral("FAILED"), 3006, QStringLiteral("write failed"));
  EXPECT_EQ(state(fx, id), QStringLiteral("paused"));
  EXPECT_EQ(target(fx, id, kDev3).status, QStringLiteral("pending"));
  spin(300);
  EXPECT_EQ(d3->updater->state(), Updater::State::Idle);
  EXPECT_FALSE(backend.admin.resumeRelease(id, operPwd(), &error));
  EXPECT_TRUE(error.contains(QStringLiteral("阈值"))) << error.toStdString();
}

// 手动暂停（不要求口令）与继续（要求口令）：观察期暂停后继续，重新观察，再进入待确认全量
TEST_F(Rollout, ManualPauseAndResume) {
  LiveServer fx(&backend);
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  auto d1 = startDevice(fx, sharedPki().dev001, kDev1, pkg);
  ASSERT_TRUE(ready(kDev1));
  backend.openGateAndLoginAsOperator();
  const qint64 id = create(pkg, {kDev1});
  ASSERT_TRUE(backend.admin.startCanary(id, operPwd(), &error)) << error.toStdString();
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("observing")));

  ASSERT_TRUE(backend.admin.pauseRelease(id, &error)) << error.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("paused"));
  spin(500);  // 原来的观察期定时器到时也不会把已暂停的发布往前推
  EXPECT_EQ(state(fx, id), QStringLiteral("paused"));

  ASSERT_TRUE(backend.admin.resumeRelease(id, operPwd(), &error)) << error.toStdString();
  EXPECT_EQ(state(fx, id), QStringLiteral("observing"));
  ASSERT_TRUE(waitState(fx, id, QStringLiteral("awaiting_full")));
}

// 只有操作员能新建和推进发布；维护员、没登录都不行
TEST_F(Rollout, OnlyOperatorManagesReleases) {
  const QString pkg = importFirmware(QStringLiteral("2.1.0"), 5);
  LiveServer fx(&backend);
  backend.loginAsMaintainer();
  qint64 id = 0;
  EXPECT_FALSE(backend.admin.createRelease(pkg, {kDev1}, QString(), 5, &id, &error));
  backend.admin.logout();
  EXPECT_FALSE(backend.admin.createRelease(pkg, {kDev1}, QString(), 5, &id, &error));
  EXPECT_TRUE(fx.rollout->releases(10).isEmpty());

  backend.openGateAndLoginAsOperator();
  // 金丝雀必须选，且必须是这个型号、已注册的设备
  EXPECT_FALSE(backend.admin.createRelease(pkg, {}, QString(), 5, &id, &error));
  EXPECT_FALSE(backend.admin.createRelease(pkg, {QStringLiteral("DEV-999")}, QString(), 5, &id, &error));
  id = create(pkg, {kDev1});
  backend.loginAsMaintainer();
  EXPECT_FALSE(backend.admin.startCanary(id, pwd("Maint-pass-01"), &error));
  EXPECT_EQ(state(fx, id), QStringLiteral("draft"));
}
