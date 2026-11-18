#!/usr/bin/env bash
# 回到演示前的状态：停止全部进程，用 setup.sh 存的快照恢复服务端数据库、固件库、审计检查点和四台设备的分区，
# 清空运行日志。证书、密钥、许可证、固件包不动，所以几秒内完成，不用再输口令。
# 演示中任何一步卡住、或者审计日志被 tamper_audit.sh 改过，都用它重来。
source "$(dirname "$0")/lib.sh"

[ -d "$D/snapshot/data" ] || die "没有快照，先运行 demo/setup.sh"
stop_all
rm -rf "$D/data" "$D/device" "$D/logs"
cp -R "$D/snapshot/data" "$D/snapshot/device" "$D/"
mkdir -p "$D/logs" "$D/run"
say "已恢复到演示前的状态。demo/start.sh 重新启动"
