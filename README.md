# 工业固件安全升级分发系统

网络安全实践项目第 3 题：服务端向工厂各地的嵌入式设备（客户端）安全分发固件更新包。

- 架构：C/S（分发服务端 + 设备客户端 + 离线签名工具）
- 技术栈：C++17 / CMake / Qt 6 / OpenSSL 3 / SQLite
- 核心安全机制：TLS 1.3 双向证书认证（自建 CA、完整证书校验、仅 AES-256-GCM 套件）、RSA-3072-PSS 固件签名、逐片 SHA-256、防降级、A/B 分区回滚、事件落盘补传对账、审计哈希链

## 文档

- [实施方案](docs/实施方案.md)：总体思路、交付物清单、验收要求对照表、缺口清单、里程碑与分工
- [设计文档](docs/系统设计说明书.md)：功能设计与安全设计（图的源码为 Mermaid，导出的 SVG/PNG 在 [docs/diagrams](docs/diagrams/)）
- [通信协议文档](docs/通信协议文档.md)：TLS 信道规定、帧格式、消息定义、错误码
- [测试报告](docs/测试验证报告.md)：功能测试与安全测试，78 条用例（通过 74、部分通过 4，后者缺 Windows 或两台机器环境，见第 8 节）
- [自查表](docs/自查表.md)、[现场基线材料](docs/现场基线材料.md)（工况台账、设备协议台账、不可改约束清单）、[数据来源与脱敏声明](docs/数据来源与脱敏声明.md)
- 答辩用：[演示脚本](docs/演示脚本.md)（10 分钟流程、讲稿、卡住时的处理）、[代码讲解提纲](docs/代码讲解提纲.md)（按 A/B 分工的核心代码逐段讲解和常见追问）
- [docs/requirements](docs/requirements/)：《项目落地要求任务书》《资料大模板》原件

## 代码结构

| 目录 | 内容 | 现状 |
|---|---|---|
| `common/` | 协议常量、FrameCodec、配置加载、日志、网络层公共部分（FrameChannel、重连退避、信道安全接口）；固件 manifest、.fwpkg 容器和模拟固件镜像头；升级消息体编解码（UPDATE_NOTIFY、CHUNK_REQ、CHUNK_DATA）；`crypto/`（SecureBuffer、AES-256-GCM、PBKDF2、私钥文件封装、X.509 读取、SHA-256、RSA-3072-PSS 签名验签）；`security/`（TLS 配置、证书完整校验、私钥口令注入、ManifestVerifier：manifest 验签、分片哈希、整镜像校验；固件签名公钥指纹核对，两端共用） | 已实现 |
| `server/` | 分发服务端 `fwds-server`：`net/`（TcpServer、Session、ConnLimiter）、`storage/`（SQLite）、`security/`（OperatorAuth：账号口令与角色权限）、`business/`（DeviceRegistry、LoginHandler、LoginThrottle、HeartbeatMonitor、AdminService、DispatchGate、FirmwareRepo、RolloutManager、ChunkService）、`ui/`（登录、设备监控、固件库、账号管理） | 网络层、TLS、设备注册表与指纹比对、登录失败锁定、账号与角色、“允许下发”开关、设备监控界面、固件库（导入时和启动时整包检查、固件表入库、导入界面）、单台下发（开关、型号、互锁裁决，发布表留痕）、分片服务（下发通知、按请求发分片、重连后重发通知）、按分组灰度与紧急停止、设备事件入库与对账、审计哈希链、运行日志文件与“运行日志”检索页、设备侧审计类别（登录、断线、心跳超时、升级、告警）、登录时的许可证验签、启动时的程序自校验和 `--check` 部署自检已实现 |
| `client/` | 设备客户端 `fwds-client`：`net/`（TcpClient：登录、心跳、断线重连）、`security/`（UpdateValidator：下载前验签、型号、防降级三项检查；DeviceAntiRollback）、`business/`（Updater：升级状态机；Downloader：分片下载；Bootloader：启动验签、自检、回滚；Provisioner：出厂写入）、`storage/`（ResumeStore、ChunkBitmap：断点落盘；BootConfig、SlotStore：boot.json 和 A/B 分区）、`ui/` | 网络层、TLS、下载前检查、防降级、分片下载与断点续传、整包校验、A/B 分区写入、模拟重启与自动回滚已实现并接入主程序；界面显示当前固件、分区、升级状态和进度；事件 outbox（PROGRESS / RESULT / ALERT 先落盘再上报，断网恢复后按序号补传）、启动时的许可证检查（签名、设备 ID、硬件指纹、有效期）和程序自校验、演示面板（模拟断网、写入时断电、立即断电、篡改下载缓存）、运行日志写文件已实现 |
| `signer/` | 离线签发工具 `fwds-signer` | 证书子命令（`ca-init`、`issue-cert`、`revoke`、`update-crl`、`list-certs`）、固件子命令（`fsk-init`、`make-image`、`sign-fw`、`verify-fw`）、程序签名 `sign-exe`、许可证 `issue-lic` 已实现 |
| `tests/` | GoogleTest 单元测试；`attack_tools/` 是安全测试用的 Python 小工具（测试代理、连接洪泛、抓包明文搜索） | 374 条，覆盖帧编解码、配置、连接限制、加密基础件、证书校验、签发工具、TLS 双向认证、网络层（全部走真实 TLS）、账号口令与锁定、角色权限、设备注册表、设备登录（2005 / 2006 / 2007）、RSA-PSS 签名验签、manifest 解析、先验签后解析、分片与整镜像校验、.fwpkg 容器与篡改检测、升级消息体编解码、断点位图与落盘、分片下载（单片重试、窗口超时、取消、3004）、断点续传联调（断线、设备重启、服务端重启、缓存被改、固件更换）、防降级边界、boot.json 与分区写入顺序、Bootloader 决策（转正、回滚、另一分区、恢复模式）、升级状态机全流程（成功切换分区、自检失败回滚、降级被拒、写入前篡改、各阶段取消、重启途中断电）、出厂写入、服务端固件库（导入、拒绝篡改和伪造的包、重启后重新检查）、单台下发联调（正常升级、自检失败回滚、降级被拒、开关与角色、离线不下发、互锁、服务端重启后暂停）、软件保护（字符串加密、许可证签名与硬件指纹、程序被改 1 字节即被发现）、数据库结构版本、运行日志轮转与检索、设备侧审计、演示面板动作 |
| `demo/` | 答辩演示的一键脚本（准备、启动、停止、重置、篡改审计日志）和数据准备工具 `fwds-demo-seed`，见下文“答辩演示” | 已实现，2026-11-18 在 Linux 上跑通 |
| `deploy/` | 打包（去符号表、UPX、程序签名）、安装（开机自启与进程守护：systemd / launchd / 任务计划程序）、升级、回滚脚本，`.sh` 用于 Linux / macOS、`.ps1` 用于 Windows；`config/` 下是 `dev.ini`、`test.ini`、`prod.ini` 配置模板。用法见 [deploy/README.md](deploy/README.md) | Linux 版在云端演练通过；自启守护和 Windows 脚本待真机验证 |

## 构建与运行

依赖：CMake 3.20+、支持 C++17 的编译器、Qt 6.4+（Core、Network、Sql、Widgets，SQLite 驱动，OpenSSL TLS 后端）、OpenSSL 3（macOS 上跟随 Homebrew 的 Qt，可能是 4，见下文）、GoogleTest（系统没有时构建脚本会在线拉取）。

Linux、macOS、Windows 都能构建运行。打包（windeployqt、UPX、程序自签名）只做 Windows 版。

> 验证情况：Linux 版在云端容器（Ubuntu 24.04、Qt 6.4.2、OpenSSL 3.0.13）里构建并跑通全部单元测试。macOS 版 2026-11-18 在真机上验证过：Homebrew 依赖、335 条单元测试全过，本机联调（服务端 + 一台设备）上线正常，一次正常升级成功（分区 a 的 2.0.0 升到 2.1.0，活动分区切到 b）。同日 Homebrew 的 Qt 升到 6.12（改链 OpenSSL 4.1）后，在本机按自动跟随 Qt 的 OpenSSL 重新构建，335 条单元测试全过。Windows 的步骤还没有在真机上跑过。

### Linux

Ubuntu 24.04 上：

```sh
sudo apt install cmake ninja-build g++ qt6-base-dev libqt6sql6-sqlite libssl-dev libgtest-dev
```

构建并运行单元测试：

```sh
cmake --preset dev -G Ninja
cmake --build --preset dev
ctest --preset dev
```

### macOS

macOS 13 及以上，Apple 芯片和 Intel 都可以。用 Homebrew 装依赖：

```sh
xcode-select --install                                    # 编译器（Apple Clang），装过就跳过
brew install cmake ninja qt googletest                   # qt 会自动带上它用的 OpenSSL
```

构建和测试的命令与 Linux 相同：

```sh
cmake --preset dev -G Ninja
cmake --build --preset dev
ctest --preset dev
```

说明：

- 本程序必须和 Qt 的 TLS 后端用同一版 OpenSSL：一个进程里混着两版 libcrypto，TLS 相关的操作会崩溃。Homebrew 的 Qt 6.12 起链接的是 `openssl@4`，所以 macOS 上不写死 `openssl@3`：顶层 `CMakeLists.txt` 用 `otool -L` 看 Qt 的 TLS 插件（`libqopensslbackend.dylib`）链接的是哪一份 libcrypto，就用那一份，配置时会打印“Qt 的 TLS 插件用的 OpenSSL 在 …”。这和 `brew link` 了哪一版无关，不用改 Homebrew 的链接。找不到插件时退回 `openssl@3`。
- 代码按 OpenSSL 3 的接口编写，OpenSSL 3 和 4 都能编译运行（Linux、Windows 仍用 3）。程序启动时检查 Qt 加载的和本程序用的 OpenSSL 大版本一致且不低于 3，不一致就报错并拒绝启动网络，不会运行到一半崩溃。
- 不用 Homebrew 的，配置时自己加 `-DCMAKE_PREFIX_PATH=<Qt 目录> -DOPENSSL_ROOT_DIR=<OpenSSL 目录>`，OpenSSL 目录要和 Qt 用的是同一版。
- 推荐用 Homebrew 的 Qt：它带 OpenSSL TLS 后端。Qt 官方安装器的 macOS 版运行时可能找不到 OpenSSL，这时 Qt 会换成系统的 Secure Transport，程序检查到后端不是 OpenSSL 会报错并拒绝启动网络（见设计文档 10.2 节），不会降级运行。
- 换过 Qt 或 OpenSSL 版本后，删掉 `build/dev` 再重新配置，否则 CMake 会沿用缓存里旧的 OpenSSL 路径。
- 程序是普通的命令行可执行文件，不是 `.app`，从终端启动即可，下面“本机联调”的命令原样可用（macOS 默认的 zsh 也支持 `read -s`）。界面窗口有时出现在终端后面，用 Cmd-Tab 切过去。
- 开着系统防火墙时，服务端第一次监听可能弹出“是否允许接受传入网络连接”。本机联调只走 127.0.0.1，选哪个都不影响；两台机器联调要选允许。

### Windows

Windows 10/11，推荐 MSVC 2022。准备：

1. Visual Studio 2022（社区版即可），勾选“使用 C++ 的桌面开发”，它自带 CMake 和 Ninja。
2. Qt 在线安装器：选一个 Qt 6 版本下的 “MSVC 2022 64-bit”；在 “Developer and Designer Tools” 里勾选 “OpenSSL 3 Toolkit”，装好后目录里应有 `include`、`lib`、`bin`。也可以用 vcpkg 装 OpenSSL：`vcpkg install openssl:x64-windows`，目录是 `<vcpkg>\installed\x64-windows`。
3. GoogleTest 不用装，构建时在线拉取；离线时用 `vcpkg install gtest:x64-windows`，并把 vcpkg 目录加进 `CMAKE_PREFIX_PATH`。

在开始菜单打开 “Developer PowerShell for VS 2022”（让 cl.exe 可用），进入仓库根目录。下面两个目录按你的安装位置改：

```powershell
$Qt  = "C:\Qt\6.8.3\msvc2022_64"                 # Qt 套件目录，示例
$Ssl = "C:\Qt\Tools\OpenSSLv3\Win_x64"           # OpenSSL 3 目录，示例，里面有 include、lib、bin

cmake --preset dev -G Ninja -DCMAKE_PREFIX_PATH="$Qt" -DOPENSSL_ROOT_DIR="$Ssl"
cmake --build --preset dev

# 运行程序和测试前，让系统找得到 Qt 和 OpenSSL 的 DLL（只对当前窗口有效）
$env:PATH = "$Qt\bin;$Ssl\bin;$env:PATH"
ctest --preset dev
```

说明：

- 程序在 `build\dev\bin\` 下：`fwds-signer.exe`、`fwds-server.exe`、`fwds-client.exe`。下面“本机联调”里的命令把 `build/dev/bin/` 换成 `build\dev\bin\`、行尾续行符 `\` 换成 PowerShell 的反引号 `` ` ``（或写成一行）即可。
- 私钥口令在 PowerShell 里这样注入（输入不回显，Windows PowerShell 5.1 和 PowerShell 7 都能用）：

  ```powershell
  $env:FWDS_KEY_PASSPHRASE = [Net.NetworkCredential]::new('', (Read-Host "私钥口令" -AsSecureString)).Password
  .\build\dev\bin\fwds-server.exe --config local\dev.local.ini
  ```

  程序读取后会清除这个变量；每个 PowerShell 窗口单独设置，互不影响。签发工具在控制台里直接提示输入口令。
- 启动时报“Qt 没有加载 OpenSSL 运行库（当前 TLS 后端：schannel）”说明 `libssl-3-x64.dll`、`libcrypto-3-x64.dll` 不在 PATH 里也不在 exe 旁边。程序只用 OpenSSL 后端，不会退回 Windows 自带的 Schannel。
- Windows 上 Qt 设置不了 NTFS 权限，私钥文件“仅所有者可读写”不生效（单元测试里对应的两处权限断言在 Windows 上不检查）。私钥本身是 AES-256-GCM 加密的，`local\` 放在自己的用户目录下即可。
- 用 MinGW 也可以：Qt 选 MinGW 套件，OpenSSL 用 MSYS2 的 `mingw-w64-x86_64-openssl`，在 Qt 自带的 MinGW 命令行里构建。这条路没有验证过。
- 两台机器联调时，服务端 `listen_address` 改成本机局域网地址，Windows 防火墙弹窗时允许专用网络。

打包成可以拷到干净机器上运行的安装包（演示机不用装 Qt），以及安装、升级、回滚，见 [deploy/README.md](deploy/README.md)。

### 答辩演示（一键脚本，推荐）

现场演示不要从零手动建证书、建账号、注册设备：步骤多，任何一步输错都会卡住。`demo/` 下的脚本把这些准备一次做完，并且随时能在几秒内回到演示前的状态。适用于 macOS 和 Linux（Windows 没有对应脚本，按下面“本机联调”手动操作）。演示流程、讲稿和出错时怎么办见[演示脚本](docs/演示脚本.md)。

前一天晚上，在演示用的电脑上（许可证绑定本机硬件指纹，换电脑要重新准备）：

```sh
rm -rf build/dev                                   # macOS 上换过 Qt / OpenSSL 必须先删（Qt 6.12 改用 OpenSSL 4）
cmake --preset dev -G Ninja && cmake --build --preset dev
demo/setup.sh                                      # 约 1 分钟，问两个口令，见下
```

`setup.sh` 只问两个口令：**演示密钥口令**（CA、固件签名密钥、全部私钥共用，至少 12 个字符）和**演示账号口令**（三个账号共用，至少 10 个字符，含字母和数字）。口令只在运行时输入，不写进任何文件，记在纸上。它生成的东西都在 `local/demo/` 下（不进仓库）：

| 内容 | 说明 |
|---|---|
| 证书与密钥 | 自建 CA，服务端证书（名称 127.0.0.1），DEV-001 ~ DEV-004 的设备证书和许可证，固件签名密钥 FSK；私钥都是 AES-256-GCM 封装 |
| 固件包 | 2.0.0（安全版本号 4，出厂）、2.1.0（5，正常升级，32 MB）、2.2.0（6，自检必定失败，演示回滚）、1.9.0（3，演示防降级） |
| 设备 | 四台都已出厂写入 2.0.0。DEV-001、DEV-003、DEV-004 分组 `line-A`；DEV-002 分组 `canary`，经限速 2 MB/s 的代理连接，下载 2.1.0 约 16 秒，来得及演示进度和紧急停止 |
| 服务端数据 | 账号 `maint01`（维护员）、`oper01`（操作员）、`audit01`（审计员），四台设备已注册，2.1.0、2.2.0、1.9.0 已导入固件库。由 `fwds-demo-seed` 调用和界面相同的 `AdminService` 完成，每一步都记进审计日志 |
| 演示参数 | 灰度观察期 15 秒（默认 30），设备模拟重启 8 秒（默认 2），方便现场讲解和点“模拟断网” |

演示时：

```sh
demo/reset.sh            # 回到演示前的状态（停进程、从快照恢复数据库、固件库和设备分区），几秒完成
demo/start.sh            # 输入演示密钥口令；后台启动服务端、慢速代理和四台设备，终端立即返回
#   ... 演示 ...
demo/tamper_audit.sh     # 场景 5：绕过程序用 sqlite3 改一条审计日志，再让审计员校验
demo/stop.sh             # 全部停止（数据保留）
```

- 只有 DEV-001、DEV-002 显示窗口，DEV-003、DEV-004 无界面运行，减少窗口互相遮挡。macOS 上被完全挡住的 Qt 窗口不会重绘，看起来像卡住，点一下窗口就好；摆窗口时尽量不重叠。
- `demo/start.sh` 跳过已在运行的进程：服务端被停掉后再运行一次即可补起来；`demo/start.sh DEV-001` 只启动一台设备，`demo/stop.sh server` 只停服务端。
- 每个进程的输出在 `local/demo/logs/<名字>.out`，启动失败先看这里（常见原因：口令输错、端口被占用、没在这台电脑上 setup）。
- 重置后服务端是新启动的，“允许下发”回到关闭，要先用 `maint01` 打开。
- 想从头重新生成全部证书和密钥，再运行一次 `demo/setup.sh`（会先确认再删除 `local/demo/`）。

### 本机联调（手动，了解每一步）

下面是不用脚本、一步步手动搭起来的做法，`demo/setup.sh` 做的就是这些步骤。答辩时被问到“证书怎么签的、设备怎么注册的”，按这一节讲。

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

# 3b. 给设备签发许可证（设计第 15 节）：绑定设备 ID 和本机硬件指纹，拷到别的机器上设备就不运行。
#     提示输入 FSK 口令；dev 模板的 license_file 指向 local/lic/DEV-001.lic
mkdir -p local/lic
build/dev/bin/fwds-signer issue-lic --fsk-dir local/fsk --device-id DEV-001 \
    --hw-fingerprint "$(build/dev/bin/fwds-client --hw-fingerprint)" --out local/lic/DEV-001.lic

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

多开设备：再签一张 `DEV-002` 的证书和一份 `DEV-002` 的许可证，复制一份配置（命名为 `*.local.ini`），改 `device_id` 和 `[client]` 的 `cert_file`、`key_file`、`license_file`、`data_dir`（每台设备一个数据目录）。

开发版（`dev` 预设）没有程序签名文件时只在启动日志里警告；Release 版缺签名文件就拒绝运行，要先用 `deploy/package.sh` / `package.ps1` 打包（见 [deploy/README.md](deploy/README.md)）。

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

设备出厂固件为 2.0.0（安全版本号 4）。用签发工具再做三个包，由维护员导入固件库，操作员逐个下发（`demo/setup.sh` 已经做好这三个包并导入，答辩时的完整流程见[演示脚本](docs/演示脚本.md)）：

| 场景 | 固件包 | 设备上的结果 | 服务端“设备监控”页 |
|---|---|---|---|
| 正常升级 | 2.1.0，安全版本号 5 | 下载、校验、写入备用分区、重启、转正，活动分区切换 | 进度条走完，升级状态 `SUCCESS`，固件版本变为 2.1.0 |
| 自检失败回滚 | 2.2.0，安全版本号 6，`make-image --selftest-fail` | 写入、重启后自检不过，自动回到原分区 | 升级状态 `ROLLED_BACK`，固件版本不变 |
| 降级被拒 | 1.9.0，安全版本号 3 | 验签通过但安全版本号低于本机最小值，`3003` 拒绝，一个分片都不下载 | 升级状态 `FAILED`，固件版本不变 |

服务端不拦旧版本：防降级由设备自己把关，演示的正是“服务端即使下发了旧固件，设备也不装”。拒绝和回滚的原因（`3003`、`3007`）由设备作为 ALERT / RESULT 事件上报，服务端“设备事件…”、“审计日志”（UPGRADE、SECURITY 类）和“运行日志”页都能看到。这三个场景也由单元测试 `Dispatch.*` 走真实 TLS 自动跑一遍。

### 演示面板与运行日志

设备客户端主窗口中部是“演示面板”，用来现场制造故障：

| 按钮 | 做什么 | 用来演示 |
|---|---|---|
| 模拟断网 / 恢复网络 | 断开连接（不发 BYE），断网期间重连都当作网络不可达；恢复后立即重连 | 下载中断网再恢复，从断点续传；离线运行界面不卡；断网期间的事件恢复后补传 |
| 写入到 50% 时断电 | 勾选后，下一次升级写分区进度到 50% 时程序当场结束 | 重新启动后仍运行原固件，可以重新升级（FT-14） |
| 立即断电 | 程序当场结束，不做任何收尾 | 例如在“重启中”断电，下次启动由 Bootloader 补完升级或回滚 |
| 篡改下载缓存 | 把 `download/` 里的 `.part` 改掉一个字节 | 断网时篡改、恢复后续传前重验发现并重下那一片；或在下载中篡改，写入前整镜像再验拒绝（`3005`） |

两端的运行日志除了输出到终端，还写进文件并按大小轮转：服务端在 `[server] log_dir`（dev 模板为 `local/logs/fwds-server.log`），设备在各自 `data_dir/logs/fwds-client.log`；`[log] max_file_kb`、`max_files` 控制轮转。服务端“运行日志”页（所有角色可看）按设备、级别、模块、时间段、关键字检索这些文件，用来定位故障。

说明：

- 地址、端口、设备 ID、证书路径、证书有效期上限和协议参数全部来自 `--config` 指定的配置文件，源码里不写死。`test.ini`、`prod.ini` 中的 `<...>` 占位符没改就启动会报错退出。现场用的配置复制到仓库之外或命名为 `*.local.ini`（已在 `.gitignore` 中）。
- 私钥文件用 AES-256-GCM 封装（口令经 PBKDF2-HMAC-SHA256 派生），口令不写入任何配置文件。缺少证书、私钥或口令时程序不会启动网络。
- 证书有效期上限在配置 `[tls]` 的 `max_ca_cert_days`（默认 365）和 `max_cert_days`（默认 90）里：签发工具不签超过上限的证书，两端也不接受。这两个值就是本项目定下的上限，需要调整时只改这两项。
- 单元测试用到的 CA 和证书在测试运行时现场生成，仓库里没有任何测试私钥。
