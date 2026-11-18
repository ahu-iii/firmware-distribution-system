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
| `common/` | 协议常量、FrameCodec、配置加载、日志、网络层公共部分（FrameChannel、重连退避、信道安全接口）；固件 manifest、.fwpkg 容器和模拟固件镜像头；升级消息体编解码（UPDATE_NOTIFY、CHUNK_REQ、CHUNK_DATA）；`crypto/`（SecureBuffer、AES-256-GCM、PBKDF2、私钥文件封装、X.509 读取、SHA-256、RSA-3072-PSS 签名验签）；`security/`（TLS 配置、证书完整校验、私钥口令注入、ManifestVerifier：manifest 验签、分片哈希、整镜像校验；固件签名公钥指纹核对，两端共用） | 已实现 |
| `server/` | 分发服务端 `fwds-server`：`net/`（TcpServer、Session、ConnLimiter）、`storage/`（SQLite）、`security/`（OperatorAuth：账号口令与角色权限）、`business/`（DeviceRegistry、LoginHandler、LoginThrottle、HeartbeatMonitor、AdminService、DispatchGate、FirmwareRepo、RolloutManager、ChunkService）、`ui/`（登录、设备监控、固件库、账号管理） | 网络层、TLS、设备注册表与指纹比对、登录失败锁定、账号与角色、“允许下发”开关、设备监控界面、固件库（导入时和启动时整包检查、固件表入库、导入界面）、单台下发（开关、型号、互锁裁决，发布表留痕）、分片服务（下发通知、按请求发分片、重连后重发通知）已实现；许可证验签（接入点已留）、按分组灰度与紧急停止、设备事件入库、审计哈希链待实现 |
| `client/` | 设备客户端 `fwds-client`：`net/`（TcpClient：登录、心跳、断线重连）、`security/`（UpdateValidator：下载前验签、型号、防降级三项检查；DeviceAntiRollback）、`business/`（Updater：升级状态机；Downloader：分片下载；Bootloader：启动验签、自检、回滚；Provisioner：出厂写入）、`storage/`（ResumeStore、ChunkBitmap：断点落盘；BootConfig、SlotStore：boot.json 和 A/B 分区）、`ui/` | 网络层、TLS、下载前检查、防降级、分片下载与断点续传、整包校验、A/B 分区写入、模拟重启与自动回滚已实现并接入主程序；界面显示当前固件、分区、升级状态和进度；事件 outbox（PROGRESS / RESULT / ALERT 落盘上报）、许可证、演示面板待实现 |
| `signer/` | 离线签发工具 `fwds-signer` | 证书子命令（`ca-init`、`issue-cert`、`revoke`、`update-crl`、`list-certs`）和固件子命令（`fsk-init`、`make-image`、`sign-fw`、`verify-fw`）已实现；程序签名、许可证待实现 |
| `tests/` | GoogleTest 单元测试 | 299 条，覆盖帧编解码、配置、连接限制、加密基础件、证书校验、签发工具、TLS 双向认证、网络层（全部走真实 TLS）、账号口令与锁定、角色权限、设备注册表、设备登录（2005 / 2006 / 2007）、RSA-PSS 签名验签、manifest 解析、先验签后解析、分片与整镜像校验、.fwpkg 容器与篡改检测、升级消息体编解码、断点位图与落盘、分片下载（单片重试、窗口超时、取消、3004）、断点续传联调（断线、设备重启、服务端重启、缓存被改、固件更换）、防降级边界、boot.json 与分区写入顺序、Bootloader 决策（转正、回滚、另一分区、恢复模式）、升级状态机全流程（成功切换分区、自检失败回滚、降级被拒、写入前篡改、各阶段取消、重启途中断电）、出厂写入、服务端固件库（导入、拒绝篡改和伪造的包、重启后重新检查）、单台下发联调（正常升级、自检失败回滚、降级被拒、开关与角色、离线不下发、互锁、服务端重启后暂停） |
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

# 3. 生成固件签名密钥，把显示的公钥指纹填进配置（见下面“固件签名”一节）。
#    服务端和设备都只认这把公钥，[server] 和 [client] 里各有一项 fsk_pub_sha256
build/dev/bin/fwds-signer fsk-init --fsk-dir local/fsk
cp deploy/config/dev.ini local/dev.local.ini      # 然后把两处 fsk_pub_sha256=<FSK 公钥指纹> 改成显示的指纹

# 4. 两个终端分别启动。私钥口令通过环境变量注入，程序读取后立即从环境中清除
#    （read -s 不回显、不进命令历史；加 --headless 则不显示界面）
read -s FWDS_KEY_PASSPHRASE && export FWDS_KEY_PASSPHRASE
build/dev/bin/fwds-server --config local/dev.local.ini

#    设备端另外需要一份出厂固件，见下面“设备固件与 A/B 分区”一节
read -s FWDS_KEY_PASSPHRASE && export FWDS_KEY_PASSPHRASE
build/dev/bin/fwds-client --config local/dev.local.ini
```

服务端第一次启动时账号表是空的，界面会先要求创建一个维护员账号（口令至少 10 个字符，含字母和数字）。之后：

1. 用维护员登录，在“设备监控”页点“注册设备…”，选择 `local/pki/DEV-001/device.pem`，填型号（如 `PLC-X200`）和分组。设备 ID 和证书指纹从证书里读取；没注册的设备登录会得到 `2005`。
2. 其他角色的账号在“账号管理”页创建。新账号第一次登录必须先改掉初始口令。
3. 窗口右上角的“允许下发”默认关闭（只监控），只有维护员能打开；服务端每次重启后回到关闭。
4. 维护员在“固件库”页点“导入固件包…”选择 .fwpkg。服务端把它复制进固件库目录并整包检查（验签、逐片哈希、整镜像哈希），通过才入库；被改过的包、别的密钥签的包会被拒绝并记安全日志。
5. 操作员在“固件库”页选中一个固件，点“下发到设备…”，选一台在线设备并确认。升级状态和进度在“设备监控”页看，下发记录在“固件库”页下方。下发需要维护员先打开“允许下发”；设备正在升级、离线、型号不符时会被拒绝并说明原因。

数据库文件的位置在配置 `[server] db_file`（dev 模板为 `local/data/fwds-server.db`），固件库目录在 `[server] firmware_dir`（dev 模板为 `local/data/firmware`）。加 `--headless` 运行时没有账号登录，只做监控，不能执行管理操作。

多开设备：再签一张 `DEV-002` 的证书，复制一份配置（命名为 `*.local.ini`），改 `device_id` 和 `[client]` 的 `cert_file`、`key_file`、`data_dir`（每台设备一个数据目录）。

吊销演练：`fwds-signer revoke --ca-dir local/ca --name DEV-001`，然后用新的 `local/ca/crl.pem` 覆盖配置里 `crl_file` 指向的文件；服务端在下一次握手前自动重新加载，该设备重连即被拒绝。CRL 默认 30 天有效，到期前用 `fwds-signer update-crl` 刷新。

### 固件签名

固件签名密钥 FSK 和 CA 一样只放在签发主机上，下面的文件同样生成在 `local/` 下。

```sh
# 1. 生成固件签名密钥（RSA-3072）。提示设置 FSK 口令；结束时显示公钥指纹，记下来供分发公钥时核对
build/dev/bin/fwds-signer fsk-init --fsk-dir local/fsk

# 2. 生成一个模拟固件镜像（课程原型没有真实固件：37 字节的头 + 随机载荷）
build/dev/bin/fwds-signer make-image --model PLC-X200 --fw-version 2.1.0 --size 10485760 --out fw_v2.1.0.bin

# 3. 给固件镜像签名并打包。提示输入 FSK 口令；写出 .fwpkg 后会自动用公钥完整检查一遍
build/dev/bin/fwds-signer sign-fw --fsk-dir local/fsk --image fw_v2.1.0.bin \
    --model PLC-X200 --fw-version 2.1.0 --security-version 5 --note "发布说明" \
    --out local/fw/fw_v2.1.0_sv5.fwpkg

# 4. 任何拿到公钥的人都可以检查一个固件包（不需要口令）
build/dev/bin/fwds-signer verify-fw --pubkey local/fsk/fsk.pub.pem --pkg local/fw/fw_v2.1.0_sv5.fwpkg
```

`local/fsk/fsk.key` 是 AES-256-GCM 封装的私钥，不离开签发主机；`fsk.pub.pem` 是公钥，分发给服务端和设备。`--security-version` 只增不减：修了安全漏洞的版本加 1，设备据此拒绝装回旧固件。

### 设备固件与 A/B 分区

设备端只装“指纹与配置一致的那把 FSK 公钥”签过的固件。准备一台模拟设备：

```sh
# 1. 用“本机联调”第 3 步准备好的 local/dev.local.ini（已填好 fsk_pub_sha256）

# 2. 出厂写入：给空设备的分区 a 装第一份固件（先用 make-image、sign-fw 做一个 2.0.0 的包）。不需要私钥口令
build/dev/bin/fwds-client --config local/dev.local.ini --provision local/fw/fw_v2.0.0_sv4.fwpkg
```

设备数据目录（`[client] data_dir`，dev 模板为 `local/device/DEV-001`）里是模拟的 Flash：`slot_a/`、`slot_b/` 各放一份固件（`firmware.bin`、`manifest.json`、`manifest.sig`），`boot.json` 记录活动分区、待确认分区、启动次数和最小安全版本号，`download/` 是下载缓存。

- 每次启动先由 Bootloader 对分区验签，再联网；LOGIN 上报的版本和活动分区就是它选定的。
- 升级时新固件只写非活动分区，写完模拟重启；验签、自检通过才切换分区并提升最小安全版本号，否则自动回到原分区（`ROLLED_BACK`）。
- 不做出厂写入也可以：空设备以“恢复模式”上线，等服务端推送第一份固件。

### 三个演示场景

设备出厂固件为 2.0.0（安全版本号 4）。用签发工具再做三个包，由维护员导入固件库，操作员逐个下发：

| 场景 | 固件包 | 设备上的结果 | 服务端“设备监控”页 |
|---|---|---|---|
| 正常升级 | 2.1.0，安全版本号 5 | 下载、校验、写入备用分区、重启、转正，活动分区切换 | 进度条走完，升级状态 `SUCCESS`，固件版本变为 2.1.0 |
| 自检失败回滚 | 2.2.0，安全版本号 6，`make-image --selftest-fail` | 写入、重启后自检不过，自动回到原分区 | 升级状态 `ROLLED_BACK`，固件版本不变 |
| 降级被拒 | 1.9.0，安全版本号 3 | 验签通过但安全版本号低于本机最小值，`3003` 拒绝，一个分片都不下载 | 升级状态 `FAILED`，固件版本不变 |

服务端不拦旧版本：防降级由设备自己把关，演示的正是“服务端即使下发了旧固件，设备也不装”。拒绝和回滚的原因（`3003`、`3007`）目前在设备端界面和日志里；作为 ALERT / RESULT 事件上报到服务端在“事件补传对账”一步加入。这三个场景也由单元测试 `Dispatch.*` 走真实 TLS 自动跑一遍。

说明：

- 地址、端口、设备 ID、证书路径、证书有效期上限和协议参数全部来自 `--config` 指定的配置文件，源码里不写死。`test.ini`、`prod.ini` 中的 `<...>` 占位符没改就启动会报错退出。现场用的配置复制到仓库之外或命名为 `*.local.ini`（已在 `.gitignore` 中）。
- 私钥文件用 AES-256-GCM 封装（口令经 PBKDF2-HMAC-SHA256 派生），口令不写入任何配置文件。缺少证书、私钥或口令时程序不会启动网络。
- 证书有效期上限在配置 `[tls]` 的 `max_ca_cert_days`（默认 365）和 `max_cert_days`（默认 90）里：签发工具不签超过上限的证书，两端也不接受。这两个值就是本项目定下的上限，需要调整时只改这两项。
- 单元测试用到的 CA 和证书在测试运行时现场生成，仓库里没有任何测试私钥。
