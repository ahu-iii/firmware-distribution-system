# 工业固件安全升级分发系统

网络安全实践项目第 3 题：服务端向工厂各地的嵌入式设备（客户端）安全分发固件更新包。

- 架构：C/S（分发服务端 + 设备客户端 + 离线签名工具）
- 技术栈：C++17 / CMake / Qt 6 / OpenSSL 3 / SQLite
- 核心安全机制：RSA-3072-PSS 固件签名、逐片 SHA-256、防降级、双向认证握手（X25519 + 签名）、AES-256-GCM 会话加密与防重放、A/B 分区回滚、审计哈希链

## 文档

- [实施方案](docs/实施方案.md)（总体思路、技术栈、里程碑与分工）
- [系统设计说明书](docs/系统设计说明书.md)（架构图源码为 Mermaid，导出的 SVG/PNG 在 [docs/diagrams](docs/diagrams/)）
- [通信协议文档](docs/通信协议文档.md)（帧格式、消息定义、握手与加密、错误码）
- [测试验证报告](docs/测试验证报告.md)（v0.1 为设计阶段测试方案：64 条用例与预期结果，实际结果在测试阶段填写）

## 代码结构

| 目录 | 内容 | 现状 |
|---|---|---|
| `common/` | 协议常量、FrameCodec、配置加载、日志、网络层公共部分（FrameChannel、重连退避、信道安全接口） | 已实现 |
| `server/` | 分发服务端 `fwds-server`：`net/`（TcpServer、Session、ConnLimiter）、`business/`、`ui/` | 网络层已实现；登录检查和界面为骨架 |
| `client/` | 设备客户端 `fwds-client`：`net/`（TcpClient：登录、心跳、断线重连）、`ui/` | 网络层已实现；界面为骨架 |
| `signer/` | 离线签发工具 `fwds-signer` | 只有子命令框架 |
| `tests/` | GoogleTest 单元测试 | 47 条，覆盖帧编解码、配置、连接限制、网络层 |
| `deploy/config/` | `dev.ini`、`test.ini`、`prod.ini` 配置模板 | 已提供 |

## 构建与运行

依赖：CMake 3.20+、支持 C++17 的编译器、Qt 6.4+（Core、Network、Widgets）、GoogleTest（系统没有时构建脚本会在线拉取）。Ubuntu 24.04 上：

```sh
sudo apt install cmake ninja-build g++ qt6-base-dev libgtest-dev
```

构建并运行单元测试：

```sh
cmake --preset dev -G Ninja
cmake --build --preset dev
ctest --preset dev
```

本机联调（两个终端；加 `--headless` 则不显示界面）：

```sh
build/dev/bin/fwds-server --config deploy/config/dev.ini
build/dev/bin/fwds-client --config deploy/config/dev.ini
```

说明：

- 地址、端口、设备 ID 和协议参数全部来自 `--config` 指定的配置文件，源码里不写死。`test.ini`、`prod.ini` 中的 `<...>` 占位符没改就启动会报错退出。现场用的配置复制到仓库之外或命名为 `*.local.ini`（已在 `.gitignore` 中）。
- **TLS 层尚未实现。** `dev` 预设打开了 `FWDS_DEV_PLAINTEXT`，两端用明文信道联调网络层，启动时会打印一条 SECURITY 告警。`release` 预设不含明文信道，在 TLS 层合入之前程序会拒绝启动网络。TLS 层合入后删除这个开关。
