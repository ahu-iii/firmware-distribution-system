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
| `common/` | 协议常量、FrameCodec、配置加载、日志、网络层公共部分（FrameChannel、重连退避、信道安全接口）；固件 manifest 和 .fwpkg 容器；`crypto/`（SecureBuffer、AES-256-GCM、PBKDF2、私钥文件封装、X.509 读取、SHA-256、RSA-3072-PSS 签名验签）；`security/`（TLS 配置、证书完整校验、私钥口令注入、ManifestVerifier：manifest 验签、分片哈希、整镜像校验） | 已实现 |
| `server/` | 分发服务端 `fwds-server`：`net/`（TcpServer、Session、ConnLimiter）、`storage/`（SQLite）、`security/`（OperatorAuth：账号口令与角色权限）、`business/`（DeviceRegistry、LoginHandler、LoginThrottle、HeartbeatMonitor、AdminService、DispatchGate）、`ui/`（登录、设备监控、账号管理） | 网络层、TLS、设备注册表与指纹比对、登录失败锁定、账号与角色、“允许下发”开关、设备监控界面已实现；许可证验签（接入点已留）、固件库、灰度发布、审计哈希链待实现 |
| `client/` | 设备客户端 `fwds-client`：`net/`（TcpClient：登录、心跳、断线重连）、`security/`（UpdateValidator：下载前验签、型号、防降级三项检查）、`ui/` | 网络层、TLS、下载前检查已实现（防降级判定为接入点，随 A/B 分区实现）；升级状态机、续传、Bootloader 待实现；界面为骨架 |
| `signer/` | 离线签发工具 `fwds-signer` | 证书子命令（`ca-init`、`issue-cert`、`revoke`、`update-crl`、`list-certs`）和固件签名子命令（`fsk-init`、`sign-fw`、`verify-fw`）已实现；程序签名、许可证待实现 |
| `tests/` | GoogleTest 单元测试 | 203 条，覆盖帧编解码、配置、连接限制、加密基础件、证书校验、签发工具、TLS 双向认证、网络层（全部走真实 TLS）、账号口令与锁定、角色权限、设备注册表、设备登录（2005 / 2006 / 2007）、RSA-PSS 签名验签、manifest 解析、先验签后解析、分片与整镜像校验、.fwpkg 容器与篡改检测 |
| `deploy/config/` | `dev.ini`、`test.ini`、`prod.ini` 配置模板 | 已提供 |

## 构建与运行

依赖：CMake 3.20+、支持 C++17 的编译器、Qt 6.4+（Core、Network、Sql、Widgets，SQLite 驱动）、OpenSSL 3、GoogleTest（系统没有时构建脚本会在线拉取）。Ubuntu 24.04 上：

```sh
sudo apt install cmake ninja-build g++ qt6-base-dev libqt6sql6-sqlite libssl-dev libgtest-dev
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

服务端第一次启动时账号表是空的，界面会先要求创建一个维护员账号（口令至少 10 个字符，含字母和数字）。之后：

1. 用维护员登录，在“设备监控”页点“注册设备…”，选择 `local/pki/DEV-001/device.pem`，填型号（如 `PLC-X200`）和分组。设备 ID 和证书指纹从证书里读取；没注册的设备登录会得到 `2005`。
2. 其他角色的账号在“账号管理”页创建。新账号第一次登录必须先改掉初始口令。
3. 窗口右上角的“允许下发”默认关闭（只监控），只有维护员能打开；服务端每次重启后回到关闭。

数据库文件的位置在配置 `[server] db_file`（dev 模板为 `local/data/fwds-server.db`）。加 `--headless` 运行时没有账号登录，只做监控，不能执行管理操作。

多开设备：再签一张 `DEV-002` 的证书，复制一份配置（命名为 `*.local.ini`），改 `device_id` 和 `[client]` 的 `cert_file`、`key_file`。

吊销演练：`fwds-signer revoke --ca-dir local/ca --name DEV-001`，然后用新的 `local/ca/crl.pem` 覆盖配置里 `crl_file` 指向的文件；服务端在下一次握手前自动重新加载，该设备重连即被拒绝。CRL 默认 30 天有效，到期前用 `fwds-signer update-crl` 刷新。

### 固件签名

固件签名密钥 FSK 和 CA 一样只放在签发主机上，下面的文件同样生成在 `local/` 下。

```sh
# 1. 生成固件签名密钥（RSA-3072）。提示设置 FSK 口令；结束时显示公钥指纹，记下来供分发公钥时核对
build/dev/bin/fwds-signer fsk-init --fsk-dir local/fsk

# 2. 给一个固件镜像签名并打包。提示输入 FSK 口令；写出 .fwpkg 后会自动用公钥完整检查一遍
build/dev/bin/fwds-signer sign-fw --fsk-dir local/fsk --image fw_v2.1.0.bin \
    --model PLC-X200 --fw-version 2.1.0 --security-version 5 --note "发布说明" \
    --out local/fw/fw_v2.1.0_sv5.fwpkg

# 3. 任何拿到公钥的人都可以检查一个固件包（不需要口令）
build/dev/bin/fwds-signer verify-fw --pubkey local/fsk/fsk.pub.pem --pkg local/fw/fw_v2.1.0_sv5.fwpkg
```

`local/fsk/fsk.key` 是 AES-256-GCM 封装的私钥，不离开签发主机；`fsk.pub.pem` 是公钥，分发给服务端和设备。`--security-version` 只增不减：修了安全漏洞的版本加 1，设备据此拒绝装回旧固件。

说明：

- 地址、端口、设备 ID、证书路径、证书有效期上限和协议参数全部来自 `--config` 指定的配置文件，源码里不写死。`test.ini`、`prod.ini` 中的 `<...>` 占位符没改就启动会报错退出。现场用的配置复制到仓库之外或命名为 `*.local.ini`（已在 `.gitignore` 中）。
- 私钥文件用 AES-256-GCM 封装（口令经 PBKDF2-HMAC-SHA256 派生），口令不写入任何配置文件。缺少证书、私钥或口令时程序不会启动网络。
- 证书有效期上限在配置 `[tls]` 的 `max_ca_cert_days`（默认 365）和 `max_cert_days`（默认 90）里：签发工具不签超过上限的证书，两端也不接受。课程规定的上限确定后只改这两项。
- 单元测试用到的 CA 和证书在测试运行时现场生成，仓库里没有任何测试私钥。
