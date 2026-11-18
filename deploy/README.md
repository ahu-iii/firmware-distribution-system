# 部署、升级与回滚

本目录是设计文档第 8.3、8.4 节和第 15 节的实现：打包加固、干净环境安装、开机自启与进程守护、程序自身的升级与回滚。对应检查项 3-2、8-1 ~ 8-4、1-8，测试用例 FT-17 ~ FT-21、ST-31、ST-32。

| 文件 | 作用 |
|---|---|
| `package.sh` / `package.ps1` | 在签发主机上把 Release 版打成安装包：去符号表、UPX 加壳、`sign-exe` 签名（Linux、macOS / Windows） |
| `install.sh` / `install.ps1` | 在目标机器上安装服务端或一台设备，注册开机自启和守护 |
| `upgrade.sh` / `upgrade.ps1` | 把一个实例升级到新包的版本，失败自动回滚 |
| `rollback.sh` / `rollback.ps1` | 把一个实例退回升级前的版本 |
| `lib/common.sh` / `lib/common.ps1` | 上面几个脚本共用的函数（配置生成、口令保存、服务管理、备份恢复、冒烟检查） |
| `lib/run.sh` / `lib/run.ps1` | 启动器：服务管理器调用它，它取出私钥口令再启动程序 |
| `config/` | `dev.ini`、`test.ini`、`prod.ini` 配置模板 |

验证情况：Linux 版的打包、安装、升级、回滚、失败自动回滚、程序被改和许可证换机器在云端容器里跑通过（容器里没有 systemd，用 `--no-service` 安装，见 `evidence/` 下的演练记录）。systemd、launchd、任务计划程序的自启和守护，以及 Windows 的全部脚本，云端无法运行，要在真机上按本文最后一节验证。

## 安装目录

三个平台结构相同，一台机器上可以装一个服务端和多台模拟设备（“实例”是 `server` 或设备 ID）：

```
<安装目录>/
  app/<版本>/            一个版本的完整程序包（bin/ 程序和 .sig 签名文件，deploy/ 脚本和模板，VERSION）
  bin/                   启动器 run.sh / run.ps1 和共用函数，不随版本变
  state/<实例>.current   该实例当前运行的版本；升级、回滚只改这个文件
  state/<实例>.previous  升级前的版本，回滚时切回它
  config/<实例>.ini      安装脚本从模板生成的配置，不含口令和私钥
  pki/<实例>/            证书、AES-256-GCM 封装的私钥、CA 根证书、CRL、许可证 device.lic
  pki/fsk.pub.pem        固件签名公钥
  data/<实例>/           服务端的数据库和固件库，或设备的模拟 Flash 和 outbox
  audit/                 服务端审计日志检查点（和数据库分开放）
  secrets/               私钥口令：Linux 是 <实例>.pass（权限 600），Windows 是 <实例>.dpapi（DPAPI 加密）
  logs/                  运行日志 <实例>.log，以及每次安装、升级、回滚的记录
  backup/<时间>_<版本>_<实例>/   升级前的备份
  run/                   进程号、服务方式等运行时文件
```

安装目录只有运行账户能访问（Linux / macOS 用 `umask 077`，Windows 用 `icacls` 去掉继承权限）。

## 私钥口令怎么注入

口令不写进配置文件、不出现在命令行参数里（`ps` 能看到参数），安装时由安装人员输入一次：

| 平台 | 保存在哪里 | 谁能读 |
|---|---|---|
| Linux | `secrets/<实例>.pass`，权限 600 | 运行账户（和 root） |
| macOS | 当前用户的登录钥匙串，服务名 `fwds-key-passphrase` | 当前用户登录后的会话 |
| Windows | `secrets\<实例>.dpapi`，DPAPI 按当前用户加密 | 只有安装它的那个 Windows 账户；文件拷走解不开 |

启动器每次启动程序前取出口令，放进环境变量 `FWDS_KEY_PASSPHRASE`，程序读取后立即从自己的环境里清除（设计 11.3 节）。无人值守的自动重启必须能拿到口令，所以口令总要以某种形式存在这台机器上；上表是每个平台上“只有运行账户能拿到”的做法。

## 打包（签发主机上）

签名用的 FSK 私钥只在签发主机上，所以打包也在签发主机上做。

### Linux / macOS

```sh
cmake --preset release -G Ninja -DFWDS_BUILD_TESTS=OFF
cmake --build --preset release
deploy/package.sh --build-dir build/release --fsk-dir local/fsk --upx      # 提示输入 FSK 口令
```

生成 `dist/fwds-<版本>-<linux|macos>/`。Release 预设打开了 `FWDS_REQUIRE_EXE_SIGNATURE`：程序旁边没有签名文件就拒绝运行。macOS 上不做 UPX（UPX 不支持当前的 macOS 程序格式），只去符号表和签名；macOS 版依赖 Homebrew 的 Qt 和 openssl@3，目标机器上要先 `brew install qt openssl@3`。

### Windows

在 “Developer PowerShell for VS 2022” 里：

```powershell
$Qt  = "C:\Qt\6.8.3\msvc2022_64"
$Ssl = "C:\Qt\Tools\OpenSSLv3\Win_x64"
cmake --preset release -G Ninja -DCMAKE_PREFIX_PATH="$Qt" -DOPENSSL_ROOT_DIR="$Ssl" -DFWDS_BUILD_TESTS=OFF
cmake --build --preset release
powershell -ExecutionPolicy Bypass -File deploy\package.ps1 -BuildDir build\release -QtDir $Qt -OpenSslDir $Ssl `
    -FskDir local\fsk -Upx C:\tools\upx\upx.exe
```

UPX 从 <https://github.com/upx/upx/releases> 下载 win64 版解压即可。生成 `dist\fwds-<版本>-windows\`，里面带 Qt、OpenSSL 的 DLL 和 VC++ 运行库安装包，目标机器不用装 Qt。部分杀毒软件会把 UPX 加壳的程序报为可疑，演示机上把安装目录加入排除项。

### 签名之后不能再改程序

`sign-exe` 签的是 `"FWDS-EXE-1" ‖ SHA-256(程序文件)`，程序启动时用指纹已核对的 FSK 公钥校验自己（`common/security/exe_signature.h`）。所以顺序必须是“去符号表 → UPX → 签名”，签完不能再动文件。开发版（`dev` 预设）不强制：没有签名文件只警告，有签名文件但不符同样拒绝运行。

## 签发每台设备的材料

在签发主机上（命令见仓库 README“本机联调”）：服务端证书、每台设备的证书、FSK 公钥和指纹，以及每台设备的许可证。许可证绑定设备主机的硬件指纹，先在设备主机上取：

```sh
fwds-client --hw-fingerprint            # Windows：fwds-client.exe --hw-fingerprint
```

把输出的 64 位十六进制抄到签发主机：

```sh
build/dev/bin/fwds-signer issue-lic --fsk-dir local/fsk --device-id DEV-001 \
    --hw-fingerprint <上面的输出> --days 365 --out local/lic/DEV-001.lic
```

硬件指纹是操作系统给出的机器唯一标识（Linux `/etc/machine-id`，macOS IOPlatformUUID，Windows 注册表 MachineGuid）加前缀后的 SHA-256。同一台机器上多开的设备共用一个硬件指纹，许可证仍然按设备 ID 区分。

## 安装

把整个安装包目录和这台机器要用的材料拷过去，在包目录里运行。

### Linux（systemd）

```sh
# 服务端
sudo deploy/install.sh --role server --root /opt/fwds --cert-dir pki/server \
    --fsk-pub fsk.pub.pem --fsk-fingerprint <指纹> --listen 192.168.1.10
# 设备
sudo deploy/install.sh --role client --root /opt/fwds --device-id DEV-001 --cert-dir pki/DEV-001 \
    --fsk-pub fsk.pub.pem --fsk-fingerprint <指纹> --server-host 192.168.1.10 \
    --license DEV-001.lic --factory-fw fw_v2.0.0_sv4.fwpkg
```

注册为 systemd 服务 `fwds-<实例>.service`：`WantedBy=multi-user.target` 开机自启，`Restart=always` + `RestartSec=5` 进程无论怎么退出 5 秒后重新拉起，以 `sudo` 前的那个用户运行。Linux 上一律 `--headless` 运行（systemd 服务没有图形环境），服务端的管理操作在有界面的机器上做。

### macOS（launchd）

不要用 `sudo`：

```sh
deploy/install.sh --role server --root ~/fwds --cert-dir pki/server \
    --fsk-pub fsk.pub.pem --fsk-fingerprint <指纹> --listen 127.0.0.1
deploy/install.sh --role client --root ~/fwds --device-id DEV-001 --cert-dir pki/DEV-001 \
    --fsk-pub fsk.pub.pem --fsk-fingerprint <指纹> --server-host 127.0.0.1 \
    --license DEV-001.lic --factory-fw fw_v2.0.0_sv4.fwpkg
```

注册为当前用户的 launchd 代理 `~/Library/LaunchAgents/com.fwds.<实例>.plist`：`RunAtLoad` 登录后启动，`KeepAlive` 退出后 10 秒内（`ThrottleInterval`）拉起。程序在用户会话里运行，界面正常显示。要“开机自启”就在“系统设置 → 用户与群组”里打开自动登录。口令输入由 `security` 命令提示（存进钥匙串），第一次运行时系统可能弹窗询问是否允许访问钥匙串，选“始终允许”。

### Windows（任务计划程序）

普通 PowerShell 窗口即可：

```powershell
# 服务端
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Role server -Root C:\fwds -CertDir pki\server `
    -FskPub fsk.pub.pem -FskFingerprint <指纹> -Listen 192.168.1.10
# 设备
powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Role client -Root C:\fwds -DeviceId DEV-001 `
    -CertDir pki\DEV-001 -FskPub fsk.pub.pem -FskFingerprint <指纹> -ServerHost 192.168.1.10 `
    -License DEV-001.lic -FactoryFw fw_v2.0.0_sv4.fwpkg
```

注册计划任务 `FWDS-<实例>`：当前用户登录时触发，运行启动器 `run.ps1`。启动器自己循环守护：程序无论怎么退出（崩溃、任务管理器结束进程），5 秒后重新启动；启动器本身失败时任务每 1 分钟重试。要“开机自启”就用 `netplwiz` 打开自动登录。缺 VC++ 运行库时安装脚本会运行包里的 `vc_redist.x64.exe`（弹出一次管理员确认）。注册任务提示“拒绝访问”时，改用“以管理员身份运行”的 PowerShell。

### 每一步做了什么

1. **依赖检查**：包里的程序能运行（`--version`，缺 Qt、OpenSSL、VC++ 运行库时这里就失败），证书、私钥、CA、CRL、公钥、许可证、出厂固件都在；
2. **建目录**，权限只给运行账户；
3. **装入程序**到 `app/<版本>/`，写 `state/<实例>.current`；
4. **拷材料**到 `pki/`；
5. **生成配置**：从 `prod.ini`（或 `--config-template`）复制，只保留本角色的段，路径、地址、端口、指纹全部填好；留下没填的 `<...>` 占位符就中止；
6. **保存口令**（见上表）；
7. **部署自检**：用装好的程序、配置和口令跑一次 `--check`。它走程序启动时的全部检查（配置、FSK 公钥指纹、程序签名、许可证、证书和私钥口令），服务端还会建好数据库（数据库初始化）并输出数据量。不通过就删掉生成的配置和口令，中止安装；
8. **出厂固件**（设备，`--factory-fw`）：`--provision` 写入分区 a；
9. **注册自启和守护**，启动，**冒烟检查**：程序启动、5 秒后仍在运行、服务端在监听。

服务端装好后，在界面里创建维护员账号、注册设备（设备证书在设备的 `pki/<设备 ID>/device.pem`），设备就能登录。

## 升级

在**新版本**的安装包里运行，一次升级一个实例：

```sh
deploy/upgrade.sh --root /opt/fwds --instance server --expect-login 60     # Linux 加 sudo
deploy/upgrade.sh --root /opt/fwds --instance DEV-001
```

```powershell
powershell -ExecutionPolicy Bypass -File deploy\upgrade.ps1 -Root C:\fwds -Instance server -ExpectLogin 60
```

步骤（设计 8.4 节）：

1. 停止程序。不用先手工暂停发布：服务端重启后进行中的发布一律恢复为“已暂停”，要操作员确认后才继续；
2. 用旧程序跑 `--check`，记下设备、固件、发布、审计日志的条数和审计哈希链结论；
3. 备份配置、证书、固件签名公钥，服务端另备份数据库（记下 SHA-256）和审计检查点。固件库里的 `.fwpkg` 以包 ID 命名、只增不改，不备份文件本身，它们的索引（固件表）在数据库里；
4. 新版本装入 `app/<新版本>/`，`previous` 记下旧版本，`current` 改成新版本；
5. 用新程序跑 `--check`：服务端在这一步把数据库迁移到新的结构版本，然后比对数据量，必须和升级前一致；
6. 启动，冒烟检查：程序启动并保持运行、服务端在监听；`--expect-login N` 时还要在 N 秒内看到设备登录成功（设备升级默认等 60 秒）。

第 4 步之后任何一步失败都**自动回滚**，脚本以非零状态退出。

## 回滚

```sh
deploy/rollback.sh --root /opt/fwds --instance server --expect-login 60
```

```powershell
powershell -ExecutionPolicy Bypass -File deploy\rollback.ps1 -Root C:\fwds -Instance server -ExpectLogin 60
```

默认回到 `previous` 记录的版本，用该版本最新的一份备份；也可以 `--backup` 指定。步骤：停止 → `current` 切回旧版本 → 恢复配置、证书和数据库（核对 SHA-256 与备份时一致，被替换的数据库改名留着）→ 旧程序 `--check` 并与升级前的数据量比对 → 启动 → 冒烟检查。

数据一致性（设计 8.4 节“一致性”）：回滚丢掉的是升级之后服务端新写的数据。这段时间里设备上报的事件还在设备的 outbox 里，设备重新登录时服务端按 `event_ack` 对账，设备按序号补传；设备上的固件和 A/B 分区不受影响。

数据库的结构版本记在 SQLite 的 `PRAGMA user_version` 里。旧程序打开比自己新的数据库会拒绝启动并提示“先恢复升级前的数据库备份”，所以“只换回旧程序、忘了恢复数据库”不会把数据写坏。

### 手工回滚

自动回滚也失败时（例如旧版本的程序目录被删了），按顺序手工做：停止服务（`systemctl stop fwds-<实例>` / `launchctl bootout gui/$(id -u)/com.fwds.<实例>` / 在 `run\` 下建 `<实例>.stop` 文件再结束进程）→ 把 `state/<实例>.current` 改成旧版本号 → 把备份目录里的 `config.ini`、`pki/`、`fwds-server.db` 拷回原处 → 启动服务。

## 真机验证步骤

云端容器没有 systemd、launchd、任务计划程序，也没有 Windows，下面这些要在真机上做，结果和截图按自查表的证据文件名保存。

| 用例 | 步骤 | 预期 |
|---|---|---|
| FT-17 干净环境安装 | 找一台没装过开发环境的 Windows（或新建一个 macOS 用户），只拷安装包和材料，按上面“安装”一节操作；服务端和设备分装两台机器；全程录屏 | 两端启动，设备登录成功；没有手工改源码或写死地址；`logs/install-*.log` 留存 |
| FT-18 开机自启与断电恢复 | 打开自动登录；升级进行中直接断电（或强制关机）两台主机，再开机 | 两端自动启动；设备自动登录；发布为“已暂停”，继续后升级完成 |
| FT-19 进程守护 | 分别用任务管理器 / `kill -9` / 活动监视器结束 `fwds-server`、`fwds-client` 进程 | 1 分钟内（Windows 5 秒、macOS 10 秒、Linux 5 秒）自动拉起并恢复连接；`logs/<实例>.run.log`（Windows）或系统日志里有记录 |
| FT-20 系统升级 | 用 `-DFWDS_VERSION=0.2.1` 另编一版并打包，运行 `upgrade` | 记录里有备份、数据比对、冒烟检查通过；设备、固件、日志数据完整 |
| FT-21 系统回滚 | 接 FT-20 运行 `rollback`；回滚前先让设备产生一些事件 | 回到旧版本；数据库 SHA-256 与备份一致；设备重连并补传事件，序号连续 |
| ST-31 程序被修改 | 用十六进制编辑器把已安装的 `fwds-client.exe` 中间某个字节改掉，再启动 | 启动日志 `程序自校验失败`，退出码 7，拒绝运行（UPX 加壳的程序改到壳的解压代码时会直接崩溃，同样不能运行；换一个靠中间的位置改即可看到自校验的提示） |
| ST-32 许可证拷贝 | 把 DEV-001 的 `device.lic` 和配置拷到另一台机器上启动 | 启动日志 `许可证绑定的硬件指纹…与本机…不符`，退出码 8 |
| ST-32 加壳与字符串 | 用 IDA Free / Ghidra / `strings` 对比 `build\release\bin\fwds-client.exe` 和安装包里加壳后的 exe | 加壳后看不到程序里的明文字符串；签名用途前缀 `FWDS-LIC-1`、`FWDS-EXE-1` 和自校验提示在加壳前也搜不到（编译期加密） |

Windows 的五个 `.ps1` 脚本在云端无法运行，第一次在真机上用时先 `-NoService` 装一遍确认流程，再正式安装。
