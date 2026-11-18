// 联调用的服务端和设备：真实 TLS、真实 TcpServer / TcpClient。
//   LiveServer  和 fwds-server 的 main 一样接线（登录、心跳、事件入库、分片服务、发布模块、设备审计），只是没有界面
//   LiveDevice  TcpClient + 完整的升级状态机 Updater（A/B 分区、Bootloader）+ 事件 outbox，出厂固件 2.0.0
// 设备的升级结果走真实链路：Updater → EventReporter → EventOutbox → RESULT 帧 → EventStore → RolloutManager。
#pragma once

#include <QDir>
#include <QJsonObject>
#include <functional>
#include <memory>

#include "client/business/event_outbox.h"
#include "client/business/event_reporter.h"
#include "client/business/updater.h"
#include "client/net/tcp_client.h"
#include "server/business/chunk_service.h"
#include "server/business/event_store.h"
#include "server/business/heartbeat_monitor.h"
#include "server/business/login_handler.h"
#include "server/business/rollout_manager.h"
#include "server/security/device_audit.h"
#include "server/net/tcp_server.h"
#include "tests/test_device.h"
#include "tests/test_server_env.h"

namespace fwds_test {

using namespace fwds;  // 测试代码里 fwds 的类型用得太多，这里统一引入

inline fwds::ProtocolParams fastParams() {
  ProtocolParams p;
  p.loginTimeoutMs = 1000;
  p.heartbeatIntervalMs = 50;
  p.heartbeatTimeoutMs = 500;
  p.reconnectBackoffMs = {30, 30};
  p.chunkWindow = 4;
  p.chunkWindowTimeoutMs = 300;
  return p;
}

// 服务端：和 fwds-server 的 main 一样接线，只是没有界面。
struct LiveServer {
  explicit LiveServer(ServerBackend* backend) : backend(backend) {
    config.listenAddress = QHostAddress::LocalHost;
    config.listenPort = 0;
    config.maxConnectionsPerIp = 50;
    config.protocol = fastParams();
    config.rollout.observeMs = 300;  // 观察期缩短到 0.3 秒
    server = std::make_unique<TcpServer>(config, security.get());
    login = std::make_unique<LoginHandler>(config.protocol, &backend->registry, &backend->throttle);
    monitor = std::make_unique<HeartbeatMonitor>(server.get(), &backend->registry);
    events = std::make_unique<EventStore>(&backend->db, &backend->registry, server.get());
    login->setEventStore(events.get());
    chunks = std::make_unique<ChunkService>(server.get(), config.protocol);
    rollout = std::make_unique<RolloutManager>(&backend->db, config.protocol, config.rollout,
                                               &backend->registry, &backend->firmware, chunks.get(),
                                               &backend->gate);
    rollout->setAuditService(&backend->audit);
    QString error;
    EXPECT_TRUE(rollout->load(&error)) << error.toStdString();
    backend->admin.setRolloutManager(rollout.get());
    QObject::connect(events.get(), &EventStore::resultStored, rollout.get(),
                     &RolloutManager::onDeviceResult);
    QObject::connect(events.get(), &EventStore::progressStored, rollout.get(),
                     &RolloutManager::onDeviceProgress);
    QObject::connect(events.get(), &EventStore::alertStored, rollout.get(),
                     &RolloutManager::onDeviceAlert);
    deviceAudit = std::make_unique<DeviceAudit>(server.get(), events.get(), &backend->registry,
                                                &backend->audit);
    QObject::connect(server.get(), &TcpServer::sessionOpened, [this](Session* s) {
      QObject::connect(s, &Session::loginRequested, login.get(), &LoginHandler::handle);
    });
    EXPECT_TRUE(server->start());
  }
  ~LiveServer() { backend->admin.setRolloutManager(nullptr); }
  quint16 port() const { return server->serverPort(); }

  ServerBackend* backend;
  std::unique_ptr<TlsChannelSecurity> security = sharedPki().pki.security(sharedPki().server);
  ServerConfig config;
  std::unique_ptr<TcpServer> server;
  std::unique_ptr<LoginHandler> login;
  std::unique_ptr<HeartbeatMonitor> monitor;
  std::unique_ptr<EventStore> events;
  std::unique_ptr<ChunkService> chunks;
  std::unique_ptr<RolloutManager> rollout;
  std::unique_ptr<DeviceAudit> deviceAudit;
};

// 一台设备：TcpClient + Updater + EventOutbox，接线方式和 fwds-client 的 main 一样。出厂固件 2.0.0（安全版本号 4）。
struct LiveDevice {
  LiveDevice(quint16 port, const Identity& identity, const QString& deviceId, const QString& dataDir)
      : security(sharedPki().pki.security(identity)) {
    config.serverHost = QStringLiteral("127.0.0.1");
    config.serverPort = port;
    config.deviceId = deviceId;
    config.model = kTestModel;
    config.dataDir = dataDir;
    config.rebootDelayMs = 0;
    config.protocol = fastParams();
    const DeviceFirmware factory(QStringLiteral("2.0.0"), 4);
    factory.installTo(dataDir, QStringLiteral("a"));

    client = std::make_unique<TcpClient>(config, security.get());
    updater = std::make_unique<Updater>(
        config, verifier, [this](MsgType type, const QByteArray& body) { return client->send(type, body); });
    QObject::connect(client.get(), &TcpClient::frameReceived, updater.get(), &Updater::handleFrame);
    QObject::connect(client.get(), &TcpClient::stateChanged, updater.get(), [this](TcpClient::State s) {
      updater->setOnline(s == TcpClient::State::Online);
    });
    // 事件 outbox 放在设备数据目录下，和 fwds-client 一样
    outbox = std::make_unique<EventOutbox>(
        QDir(dataDir).filePath(QStringLiteral("outbox")),
        [this](MsgType type, const QByteArray& body) { return client->send(type, body); });
    QString error;
    EXPECT_TRUE(outbox->open(&error)) << error.toStdString();
    reporter = std::make_unique<EventReporter>(updater.get(), outbox.get());
    QObject::connect(client.get(), &TcpClient::loggedIn, outbox.get(), [this](const QJsonObject& r) {
      outbox->onLoggedIn(r.value(QStringLiteral("event_ack")).toInteger());
    });
    QObject::connect(client.get(), &TcpClient::heartbeatAcked, outbox.get(), [this](const QJsonObject& a) {
      outbox->onAcked(a.value(QStringLiteral("event_ack")).toInteger(-1));
    });
    QObject::connect(client.get(), &TcpClient::stateChanged, outbox.get(), [this](TcpClient::State s) {
      if (s != TcpClient::State::Online) outbox->onDisconnected();
    });
    QObject::connect(updater.get(), &Updater::rebootRequested, client.get(),
                     [this]() { client->stop(QStringLiteral("reboot")); });
    QObject::connect(updater.get(), &Updater::rebootFinished, client.get(), [this]() { client->start(); });
    QObject::connect(updater.get(), &Updater::alertRaised,
                     [this](int code, const QString&) { alerts.append(code); });
    QObject::connect(client.get(), &TcpClient::frameReceived, [this](const Frame& frame) {
      if (static_cast<MsgType>(frame.type) == MsgType::UpdateNotify) ++notifies;
    });
    QObject::connect(updater.get(), &Updater::finished,
                     [this](const QString& result, int code, const QString& detail) {
                       Q_UNUSED(code);
                       Q_UNUSED(detail);
                       results.append(result);
                     });
    client->setLoginProvider([this]() {
      QJsonObject login = updater->loginFields();
      login.insert(QStringLiteral("device_id"), config.deviceId);
      login.insert(QStringLiteral("model"), config.model);
      login.insert(QStringLiteral("ts"), QDateTime::currentMSecsSinceEpoch());
      login.insert(QStringLiteral("event_base"), outbox->confirmedSeq());
      return login;
    });
    client->setHeartbeatProvider([this]() {
      QJsonObject hb;
      hb.insert(QStringLiteral("state"), updater->stateName());
      hb.insert(QStringLiteral("progress"), updater->progress());
      return hb;
    });
    updater->powerOn();
    client->start();
  }
  QString runningVersion() const { return updater->bootState().running.version; }

  ClientConfig config;
  std::unique_ptr<TlsChannelSecurity> security;
  ManifestVerifier verifier = trustedVerifier();
  std::unique_ptr<TcpClient> client;
  std::unique_ptr<Updater> updater;
  std::unique_ptr<EventOutbox> outbox;
  std::unique_ptr<EventReporter> reporter;
  QList<int> alerts;
  QStringList results;
  int notifies = 0;  // 收到过几次 UPDATE_NOTIFY
};

}  // namespace fwds_test
