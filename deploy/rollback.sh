#!/bin/bash
# deploy/rollback.sh：把服务端或设备客户端退回升级前的版本（设计 8.4 节，检查项 1-8、8-4，FT-21）。
#   deploy/rollback.sh --root /opt/fwds --instance server [--backup <备份目录>] [--expect-login 60]
# 默认用 state/<实例>.previous 记录的版本和该版本最新的一份备份。
# 步骤：停止 → current 切回旧版本 → 恢复配置、证书和数据库（核对 SHA-256）→ 旧程序自检并与升级前的数据量比对
#       → 启动 → 冒烟检查。
# 回滚丢掉的是升级之后服务端新写的数据：设备在这段时间上报的事件还在设备的 outbox 里，
# 重新登录时服务端按 event_ack 对账，设备按序号补传（设计 4.6 节）；设备上的固件不受影响。
set -u
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ROOT="" INST="" BACKUP="" EXPECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT=$2; shift 2 ;;
    --instance) INST=$2; shift 2 ;;
    --backup) BACKUP=$2; shift 2 ;;
    --expect-login) EXPECT=$2; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) die "不认识的参数 $1" ;;
  esac
done
[ -n "$ROOT" ] && [ -n "$INST" ] || die "缺少 --root 或 --instance"
ROOT=$(cd "$ROOT" && pwd) || die "没有 $ROOT"
[ -f "$ROOT/config/$INST.ini" ] || die "$ROOT 里没有装 $INST"
ROLE=$([ "$INST" = server ] && echo server || echo client)
EXPECT=${EXPECT:-$([ "$ROLE" = server ] && echo 0 || echo 60)}
start_record "$ROOT" rollback "$INST"

if [ -z "$BACKUP" ]; then
  PREV=$(tr -d ' \r\n' <"$(previous_file "$ROOT" "$INST")" 2>/dev/null) || true
  [ -n "${PREV:-}" ] || die "没有 previous 记录（没升级过，或已经回滚过）；可以用 --backup 指定备份目录"
  # 备份目录名以 UTC 时间开头，按名字排序最后一个就是最新的
  BACKUP=$(ls -d "$ROOT/backup/"*"_${PREV}_${INST}" 2>/dev/null | sort | tail -1)
  [ -n "$BACKUP" ] || die "找不到 $INST 版本 $PREV 的备份"
fi
[ -f "$BACKUP/backup.txt" ] || die "$BACKUP 不是备份目录"
say "回滚 $INST：当前 $(current_version "$ROOT" "$INST")，目标 $(grep '^version=' "$BACKUP/backup.txt" | cut -d= -f2)"
rollback_to "$ROOT" "$INST" "$ROLE" "$BACKUP" "$EXPECT" || die "回滚失败，见上面的记录"
