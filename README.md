# 工业固件安全升级分发系统

网络安全实践项目第 3 题：服务端向工厂各地的嵌入式设备（客户端）安全分发固件更新包。

- 架构：C/S（分发服务端 + 设备客户端 + 离线签名工具）
- 技术栈：C++17 / CMake / Qt 6 / OpenSSL 3 / SQLite
- 核心安全机制：TLS 1.3 双向证书认证（自建 CA、完整证书校验、仅 AES-256-GCM 套件）、RSA-3072-PSS 固件签名、逐片 SHA-256、防降级、A/B 分区回滚、事件落盘补传对账、审计哈希链

## 文档

- [实施方案](docs/实施方案.md)：总体思路、交付物清单、验收要求对照表、缺口清单、里程碑与分工
- [设计文档](docs/系统设计说明书.md)：功能设计与安全设计（图的源码为 Mermaid，导出的 SVG/PNG 在 [docs/diagrams](docs/diagrams/)）
- [通信协议文档](docs/通信协议文档.md)：TLS 信道规定、帧格式、消息定义、错误码
- [测试报告](docs/测试验证报告.md)：功能测试与安全测试，v0.2 为设计阶段方案，78 条用例，结果在测试阶段填写
- [自查表](docs/自查表.md)（底稿）、[现场基线材料](docs/现场基线材料.md)（工况台账、设备协议台账、不可改约束清单）、[数据来源与脱敏声明](docs/数据来源与脱敏声明.md)
- [docs/requirements](docs/requirements/)：《项目落地要求任务书》《资料大模板》原件

## 代码结构

| 目录 | 内容 | 现状 |
|---|---|---|
| `common/` | 协议常量、FrameCodec、配置加载、日志、网络层公共部分（FrameChannel、重连退避、信道安全接口）；`crypto/`（SecureBuffer、AES-256-GCM、PBKDF2、私钥文件封装、X.509 读取）；`security/`（TLS 配置、证书完整校验、私钥口令注入） | 已实现 |
| `server/` | 分发服务端 `fwds-server`：`net/`（TcpServer、Session、ConnLimiter）、`business/`、`ui/` | 网络层和 TLS 已实现；登录检查已含证书名称比对，注册表、许可证待接入；界面为骨架 |
| `client/` | 设备客户端 `fwds-client`：`net/`（TcpClient：登录、心跳、断线重连）、`ui/` | 网络层和 TLS 已实现；界面为骨架 |
| `signer/` | 离线签发工具 `fwds-signer` | 证书子命令已实现（`ca-init`、`issue-cert`、`revoke`、`update-crl`、`list-certs`）；固件签名、许可证待实现 |
| `tests/` | GoogleTest 单元测试 | 109 条，覆盖帧编解码、配置、连接限制、加密基础件、证书校验、签发工具、TLS 双向认证、网络层（全部走真实 TLS） |
| `deploy/config/` | `dev.ini`、`test.ini`、`prod.ini` 配置模板 | 已提供 |

## 构建与运行

依赖：CMake 3.20+、支持 C++17 的编译器、Qt 6.4+（Core、Network、Widgets）、OpenSSL 3、GoogleTest（系统没有时构建脚本会在线拉取）。Ubuntu 24.04 上：

```sh
sudo apt install cmake ninja-build g++ qt6-base-dev libssl-dev libgtest-dev
```

构建并运行单元测试：

```sh
cmake --preset dev -G Ninja
cmake --build --preset dev
ctest --preset dev
```

### 本机联调

两端只在 TLS 1.3 双向证书认证的信道上通信，没有明文模式，所以联调前要先用签发工具建一套本机用的证书。下面的命令在仓库根目录执行，生成的文件都在 `local/` 下（已在 `.gitignore` 中，不会进仓库）。

```sh
# 1. 建 CA。提示输入 CA 口令（至少 12 个字符，输入不回显），以后每次签发、吊销都要输入
build/dev/bin/fwds-signer ca-init --ca-dir local/ca --config deploy/config/dev.ini

# 2. 签发服务端证书（名称 = 客户端配置里的 server_host）和一台设备的证书（名称 = device_id）
#    每条命令会再提示为新私钥设置口令
build/dev/bin/fwds-signer issue-cert --ca-dir local/ca --type server --name 127.0.0.1 \
    --out-dir local/pki/server --config deploy/config/dev.ini
build/dev/bin/fwds-signer issue-cert --ca-dir local/ca --type device --name DEV-001 \
    --out-dir local/pki/DEV-001 --config deploy/config/dev.ini

# 3. 两个终端分别启动。私钥口令通过环境变量注入，程序读取后立即从环境中清除
#    （read -s 不回显、不进命令历史；加 --headless 则不显示界面）
read -s FWDS_KEY_PASSPHRASE && export FWDS_KEY_PASSPHRASE
build/dev/bin/fwds-server --config deploy/config/dev.ini

read -s FWDS_KEY_PASSPHRASE && export FWDS_KEY_PASSPHRASE
build/dev/bin/fwds-client --config deploy/config/dev.ini
```

多开设备：再签一张 `DEV-002` 的证书，复制一份配置（命名为 `*.local.ini`），改 `device_id` 和 `[client]` 的 `cert_file`、`key_file`。

吊销演练：`fwds-signer revoke --ca-dir local/ca --name DEV-001`，然后用新的 `local/ca/crl.pem` 覆盖配置里 `crl_file` 指向的文件；服务端在下一次握手前自动重新加载，该设备重连即被拒绝。CRL 默认 30 天有效，到期前用 `fwds-signer update-crl` 刷新。

说明：

- 地址、端口、设备 ID、证书路径、证书有效期上限和协议参数全部来自 `--config` 指定的配置文件，源码里不写死。`test.ini`、`prod.ini` 中的 `<...>` 占位符没改就启动会报错退出。现场用的配置复制到仓库之外或命名为 `*.local.ini`（已在 `.gitignore` 中）。
- 私钥文件用 AES-256-GCM 封装（口令经 PBKDF2-HMAC-SHA256 派生），口令不写入任何配置文件。缺少证书、私钥或口令时程序不会启动网络。
- 证书有效期上限在配置 `[tls]` 的 `max_ca_cert_days`（默认 365）和 `max_cert_days`（默认 90）里：签发工具不签超过上限的证书，两端也不接受。课程规定的上限确定后只改这两项。
- 单元测试用到的 CA 和证书在测试运行时现场生成，仓库里没有任何测试私钥。
