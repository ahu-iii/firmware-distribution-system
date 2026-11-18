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
// 固件签名公钥及其指纹，两端的写法一样
const QByteArray kFsk =
    "fsk_pub_file=fsk.pub.pem\n"
    "fsk_pub_sha256=00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff\n";
// 服务端必填的数据库、固件库目录、固件签名公钥和本端证书
const QByteArray kServerTls =
    "db_file=s.db\nfirmware_dir=fw\n" + kFsk + "cert_file=s.pem\nkey_file=s.key\n";
const QByteArray kClientTls = "cert_file=d.pem\nkey_file=d.key\n";
// 设备端必填的数据目录和固件签名公钥
const QByteArray kClientDevice = "data_dir=dev1\n" + kFsk + "license_file=dev1.lic\n";
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
            kClientDevice + kClientTls + kTls),
      &cfg, &error))
      << error.toStdString();
  EXPECT_EQ(cfg.serverHost, QStringLiteral("fwds.example"));
  EXPECT_EQ(cfg.serverPort, 9443);
  EXPECT_EQ(cfg.deviceId, QStringLiteral("DEV-001"));
  EXPECT_EQ(cfg.dataDir, QStringLiteral("dev1"));
  EXPECT_EQ(cfg.licenseFile, QStringLiteral("dev1.lic"));
  EXPECT_EQ(cfg.rebootDelayMs, 2000);  // 没写就用默认值
  // 指纹统一成小写
  EXPECT_EQ(cfg.fskPubSha256,
            QStringLiteral("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
}

// 设备端的数据目录、固件签名公钥和公钥指纹缺一不可；指纹格式不对也不行
TEST_F(ConfigTest, ClientDeviceItemsAreRequired) {
  const QByteArray head =
      "[client]\nserver_host=fwds.example\nserver_port=9443\ndevice_id=DEV-001\nmodel=PLC-X200\n";
  ClientConfig cfg;
  QString error;
  EXPECT_FALSE(loadClientConfig(write(head + kClientTls + kTls), &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("data_dir")));
  EXPECT_FALSE(loadClientConfig(
      write(head + "data_dir=dev1\nfsk_pub_file=fsk.pub.pem\n" + kClientTls + kTls), &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("fsk_pub_sha256")));
  EXPECT_FALSE(loadClientConfig(
      write(head + "data_dir=dev1\nfsk_pub_file=fsk.pub.pem\nfsk_pub_sha256=abc123\n" + kClientTls + kTls),
      &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("fsk_pub_sha256")));
  // 许可证也是必填项（设计第 15 节）
  EXPECT_FALSE(loadClientConfig(write(head + "data_dir=dev1\n" + kFsk + kClientTls + kTls), &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("license_file")));
}

TEST_F(ConfigTest, ProtocolValuesAreValidated) {
  const QByteArray base = "[server]\nlisten_address=127.0.0.1\nlisten_port=9443\n[protocol]\n";
  ServerConfig cfg;
  QString error;
  // 帧长上限不能超过协议规定的 1 MB
  EXPECT_FALSE(loadServerConfig(write(base + "max_frame_body=1048577\n"), &cfg, &error));
  // 也不能小到装不下一片固件：CHUNK_DATA 是 24 字节头 + 65536 字节数据
  // （[server] 的必填项先于 [protocol] 检查，所以这里把它们也写上）
  const QByteArray full = "[server]\nlisten_address=127.0.0.1\nlisten_port=9443\ndb_file=s.db\n"
                          "firmware_dir=fw\n" + kFsk + "[protocol]\n";
  EXPECT_FALSE(loadServerConfig(write(full + "max_frame_body=65559\n"), &cfg, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("max_frame_body"))) << error.toStdString();
  error.clear();
  loadServerConfig(write(full + "max_frame_body=65560\n"), &cfg, &error);
  EXPECT_FALSE(error.contains(QStringLiteral("max_frame_body")));  // 65560 本身是允许的
  EXPECT_FALSE(loadServerConfig(write(base + "login_timeout_ms=abc\n"), &cfg, &error));
  EXPECT_FALSE(loadServerConfig(write(base + "reconnect_backoff_ms=1000,x\n"), &cfg, &error));
  // 离线判定时间必须大于心跳间隔
  EXPECT_FALSE(loadServerConfig(
      write(base + "heartbeat_interval_ms=5000\nheartbeat_timeout_ms=5000\n"), &cfg, &error));
}

// 仓库里的三份模板：dev 的路径指向本机生成的 local/ 目录，两端都只差一项：
// 固件签名公钥的指纹每台签发主机都不同，必须按 fsk-init 的输出填写；
// test / prod 的占位符没改就不能启动
TEST(ConfigTemplates, ShippedTemplatesBehaveAsDocumented) {
  const QString dir = QStringLiteral(FWDS_SOURCE_DIR "/deploy/config/");
  ServerConfig server;
  ClientConfig client;
  QString error;
  EXPECT_FALSE(loadServerConfig(dir + QStringLiteral("dev.ini"), &server, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("fsk_pub_sha256"))) << error.toStdString();
  EXPECT_FALSE(loadClientConfig(dir + QStringLiteral("dev.ini"), &client, &error));
  EXPECT_TRUE(error.contains(QStringLiteral("fsk_pub_sha256"))) << error.toStdString();
  // 把指纹填上之后（[server] 和 [client] 各一处），dev 模板就能用了
  QFile devTemplate(dir + QStringLiteral("dev.ini"));
  ASSERT_TRUE(devTemplate.open(QIODevice::ReadOnly));
  QByteArray filled = devTemplate.readAll();
  filled.replace("fsk_pub_sha256=<FSK 公钥指纹>", "fsk_pub_sha256=" + QByteArray(64, 'a'));
  QTemporaryDir tmp;
  QFile filledFile(tmp.filePath(QStringLiteral("dev.local.ini")));
  ASSERT_TRUE(filledFile.open(QIODevice::WriteOnly));
  filledFile.write(filled);
  filledFile.close();
  ASSERT_TRUE(loadServerConfig(filledFile.fileName(), &server, &error)) << error.toStdString();
  ASSERT_TRUE(loadClientConfig(filledFile.fileName(), &client, &error)) << error.toStdString();
  EXPECT_EQ(server.firmwareDir, QStringLiteral("local/data/firmware"));
  EXPECT_EQ(client.dataDir, QStringLiteral("local/device/DEV-001"));
  EXPECT_EQ(client.licenseFile, QStringLiteral("local/lic/DEV-001.lic"));
  EXPECT_EQ(server.protocol.reconnectBackoffMs, ProtocolParams().reconnectBackoffMs);
  // 分片下载的三个参数：模板里写的是协议第 8 节的默认值
  EXPECT_EQ(client.protocol.chunkWindow, 16);
  EXPECT_EQ(client.protocol.chunkWindowTimeoutMs, 10000);
  EXPECT_EQ(client.protocol.chunkRetryLimit, 3);
  EXPECT_FALSE(loadServerConfig(dir + QStringLiteral("test.ini"), &server, &error));
  EXPECT_FALSE(loadClientConfig(dir + QStringLiteral("test.ini"), &client, &error));
  EXPECT_FALSE(loadServerConfig(dir + QStringLiteral("prod.ini"), &server, &error));
  EXPECT_FALSE(loadClientConfig(dir + QStringLiteral("prod.ini"), &client, &error));
}
