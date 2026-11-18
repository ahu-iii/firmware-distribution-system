# 攻击与取证小工具

测试报告（`docs/测试验证报告.md`）安全测试用到的几个 Python 脚本，只用标准库，在 Linux 上运行，只连本机回环地址。

| 文件 | 用例 | 作用 |
|---|---|---|
| `tls_proxy.py` | FT-06、FT-08、FT-09、ST-07、ST-08、ST-26 | 夹在设备和服务端之间按 TLS 记录转发，可断网（按字节数自动断，或由一个文件控制断网和恢复）、限速、翻转记录中的 1 比特、重放记录、录下客户端字节供整段回放。只记录记录类型和长度，不记录内容 |
| `flood.py` | ST-28、ST-29 | 单 IP / 多 IP 连接洪泛，慢速握手 |
| `pcap_grep.py` | ST-06 | 在抓包文件的原始字节里搜索协议字段名（含 UPDATE_CANCEL、事件序号）、设备 ID 和固件片段 |

例：DEV-001 的配置把 `server_port` 改成 9445，经代理连服务端，登录后翻转服务端发来的第 8 条加密记录：

```sh
python3 tests/attack_tools/tls_proxy.py 9445 9443 flip 8
```

接收方应报 `bad record mac` 并断开，服务端或设备记一条 `TLS record rejected` 安全日志，随后自动重连、登录成功。

限速和受控断网（FT-08 断网期间事件落盘、ST-26 让设备停在下载阶段）：

```sh
python3 tests/attack_tools/tls_proxy.py 9445 9443 slow 1000000     # 服务端→设备限速 1 MB/s
python3 tests/attack_tools/tls_proxy.py 9445 9443 gate /tmp/net.down
touch /tmp/net.down    # 断网：立即断开现有连接，拒绝新连接
rm /tmp/net.down       # 恢复
```
