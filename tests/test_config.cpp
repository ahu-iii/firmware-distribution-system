#include <QFile>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include "common/config.h"

using namespace fwds;

namespace {

class ConfigTest : public ::testing::Test {
 protected:
  QString write(const QByteArray& content) {
    const QString path = dir_.filePath(QStringLiteral("c%1.ini").arg(counter_++));
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::WriteOnly));
    file.write(content);
    return path;
  }
  QTemporaryDir dir_;
  int counter_ = 0;
};

// 两端都必填的 TLS 配置
const QByteArray kServerTls = "db_file=s.db\ncert_file=s.pem\nkey_file=s.key\n";
const QByteArray kClientTls = "cert_file=d.pem\nkey_file=d.key\n";
const QByteArray kTls = "[tls]\nca_file=ca.pem\ncrl_file=crl.pem\n";

}  // namespace

TEST_F(ConfigTest, ServerConfigLoadsValuesAndDefaults) {
  const QString path = write("[server]\nlisten_address=127.0.0.1\nlisten_port=9443\n"
                             "max_connections_per_ip=3\n" + kServerTls + kTls +
                             "[protocol]\nheartbeat_interval_ms=2000\n"
                             "reconnect_backoff_ms=500,1000,1500\n[log]\nlevel=debug\n");
  ServerConfig cfg;
  QString error;
  ASSERT_TRUE(loadServerConfig(path, &cfg, &error)) << error.toStdString();
  EXPECT_EQ(cfg.listenAddress, QHostAddress(QStringLiteral("127.0.0.1")));
  EXPECT_EQ(cfg.listenPort, 9443);
  EXPECT_EQ(cfg.maxConnections, 200);  // 没写，用默认值
  EXPECT_EQ(cfg.maxConnectionsPerIp, 3);
  EXPECT_EQ(cfg.protocol.heartbeatIntervalMs, 2000);
  EXPECT_EQ(cfg.protocol.heartbeatTimeoutMs, 15000);
  EXPECT_EQ(cfg.protocol.reconnectBackoffMs, (QList<int>{500, 1000, 1500}));
  EXPECT_EQ(cfg.logLevel, QStringLiteral("DEBUG"));
  EXPECT_EQ(cfg.tls.caFile, QStringLiteral("ca.pem"));
  EXPECT_EQ(cfg.tls.crlFile, QStringLiteral("crl.pem"));
  EXPECT_EQ(cfg.tls.certFile, QStringLiteral("s.pem"));
  EXPECT_EQ(cfg.tls.keyFile, QStringLiteral("s.key"));
  EXPECT_EQ(cfg.tls.maxCaCertDays, 365);  // 没写，用默认值
  EXPECT_EQ(cfg.tls.maxCertDays, 90);
}

// TLS 材料的路径没有默认值：缺任何一项都不能启动，不存在“不配证书就不加密”的情况
TEST_F(ConfigTest, TlsFilesAreRequired) {
  const QByteArray server = "[server]\nlisten_address=127.0.0.1\nlisten_port=9443\n";
  ServerConfig cfg;
  QString error;
  EXPECT_FALSE(loadServerConfig(write(server + kServerTls), &cfg, &error));  // 没有 [tls]
  EXPECT_FALSE(loadServerConfig(write(server + kTls), &cfg, &error));        // 没有本端证书
  EXPECT_FALSE(loadServerConfig(
      write(server + kServerTls + "[tls]\nca_file=ca.pem\ncrl_file=<吊销列表路径>\n"), &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("crl_file")));
  ASSERT_TRUE(loadServerConfig(write(server + kServerTls + kTls), &cfg, &error));
}

// 证书有效期上限可配置（课程给出上限后只改配置）
TEST_F(ConfigTest, CertDayLimitsAreConfigurable) {
  const QByteArray base =
      "[server]\nlisten_address=127.0.0.1\nlisten_port=9443\n" + kServerTls + kTls;
  ServerConfig cfg;
  QString error;
  ASSERT_TRUE(loadServerConfig(write(base + "max_ca_cert_days=180\nmax_cert_days=30\n"), &cfg, &error));
  EXPECT_EQ(cfg.tls.maxCaCertDays, 180);
  EXPECT_EQ(cfg.tls.maxCertDays, 30);
  EXPECT_FALSE(loadServerConfig(write(base + "max_cert_days=0\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write(base + "max_cert_days=99999\n"), &cfg, &error));

  SignerConfig signer;
  ASSERT_TRUE(loadSignerConfig(
      write("[tls]\nmax_ca_cert_days=180\nmax_cert_days=30\n[signer]\ncrl_valid_days=7\n"), &signer,
      &error));
  EXPECT_EQ(signer.maxCaCertDays, 180);
  EXPECT_EQ(signer.maxCertDays, 30);
  EXPECT_EQ(signer.crlValidDays, 7);
  ASSERT_TRUE(loadSignerConfig(write("[log]\nlevel=INFO\n"), &signer, &error));  // 全用默认值
  EXPECT_EQ(signer.maxCertDays, 90);
  EXPECT_EQ(signer.crlValidDays, 30);
}

TEST_F(ConfigTest, MissingFileFails) {
  ServerConfig cfg;
  QString error;
  EXPECT_FALSE(loadServerConfig(dir_.filePath(QStringLiteral("nope.ini")), &cfg, &error));
  EXPECT_FALSE(error.isEmpty());
}

// 地址和端口没有默认值，缺了必须报错
TEST_F(ConfigTest, AddressAndPortAreRequired) {
  ServerConfig cfg;
  QString error;
  EXPECT_FALSE(loadServerConfig(write("[server]\nlisten_port=9443\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write("[server]\nlisten_address=127.0.0.1\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write("[server]\nlisten_address=127.0.0.1\nlisten_port=70000\n"),
                                &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write("[server]\nlisten_address=not-an-ip\nlisten_port=1\n"),
                                &cfg, &error));
}

TEST_F(ConfigTest, TemplatePlaceholderIsRejected) {
  ClientConfig cfg;
  QString error;
  EXPECT_FALSE(loadClientConfig(
      write("[client]\nserver_host=<服务端主机名或 IP>\nserver_port=9443\ndevice_id=D\nmodel=M\n"),
      &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("server_host")));
}

TEST_F(ConfigTest, ClientConfigLoads) {
  ClientConfig cfg;
  QString error;
  ASSERT_TRUE(loadClientConfig(
      write("[client]\nserver_host=fwds.example\nserver_port=9443\ndevice_id=DEV-001\nmodel=PLC-X200\n" +
            kClientTls + kTls),
      &cfg, &error))
      << error.toStdString();
  EXPECT_EQ(cfg.serverHost, QStringLiteral("fwds.example"));
  EXPECT_EQ(cfg.serverPort, 9443);
  EXPECT_EQ(cfg.deviceId, QStringLiteral("DEV-001"));
}

TEST_F(ConfigTest, ProtocolValuesAreValidated) {
  const QByteArray base = "[server]\nlisten_address=127.0.0.1\nlisten_port=9443\n[protocol]\n";
  ServerConfig cfg;
  QString error;
  // 帧长上限不能超过协议规定的 1 MB
  EXPECT_FALSE(loadServerConfig(write(base + "max_frame_body=1048577\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write(base + "login_timeout_ms=abc\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write(base + "reconnect_backoff_ms=1000,x\n"), &cfg, &error));
  // 离线判定时间必须大于心跳间隔
  EXPECT_FALSE(loadServerConfig(
      write(base + "heartbeat_interval_ms=5000\nheartbeat_timeout_ms=5000\n"), &cfg, &error));
}

// 仓库里的三份模板：dev 可以直接用（证书路径指向本机生成的 local/pki），
// test / prod 的占位符没改就不能启动
TEST(ConfigTemplates, ShippedTemplatesBehaveAsDocumented) {
  const QString dir = QStringLiteral(FWDS_SOURCE_DIR "/deploy/config/");
  ServerConfig server;
  ClientConfig client;
  QString error;
  EXPECT_TRUE(loadServerConfig(dir + QStringLiteral("dev.ini"), &server, &error)) << error.toStdString();
  EXPECT_TRUE(loadClientConfig(dir + QStringLiteral("dev.ini"), &client, &error)) << error.toStdString();
  EXPECT_EQ(server.protocol.reconnectBackoffMs, ProtocolParams().reconnectBackoffMs);
  EXPECT_FALSE(loadServerConfig(dir + QStringLiteral("test.ini"), &server, &error));
  EXPECT_FALSE(loadClientConfig(dir + QStringLiteral("test.ini"), &client, &error));
  EXPECT_FALSE(loadServerConfig(dir + QStringLiteral("prod.ini"), &server, &error));
  EXPECT_FALSE(loadClientConfig(dir + QStringLiteral("prod.ini"), &client, &error));
}
