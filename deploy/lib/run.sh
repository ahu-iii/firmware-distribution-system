#!/bin/bash
# 启动器（Linux / macOS）：systemd、launchd 或 --no-service 方式都通过它启动程序。
# 安装时复制到 <安装目录>/bin/run.sh；它不随版本变，升级、回滚只改 <安装目录>/state/<实例>.current。
# 用法：run.sh <安装目录> <实例> <server|client> [附加参数，如 --headless]
#
# 做三件事：
#   1. 按 state/<实例>.current 找到当前版本的程序；
#   2. 日志轮转：logs/<实例>.log 超过 10 MB 就改名为 .1（原来的 .1 变 .2……最多留 5 份）；
#   3. 取出私钥口令放进环境变量 FWDS_KEY_PASSPHRASE，再用 exec 换成程序本身
#      （进程号不变，systemd / launchd 守护的就是程序）。程序读取口令后立即从自己的环境里清除。
set -u
ROOT=$1
INST=$2
ROLE=$3
shift 3

# shellcheck source=common.sh
. "$ROOT/bin/common.sh"

VERSION=$(current_version "$ROOT" "$INST")
[ -n "$VERSION" ] || { echo "没有 $(current_file "$ROOT" "$INST")，未安装？" >&2; exit 1; }
EXE=$(exe_path "$ROOT" "$VERSION" "$ROLE")
LOG="$ROOT/logs/$INST.log"

mkdir -p "$ROOT/logs"
if [ "$(log_size "$LOG")" -gt $((10 * 1024 * 1024)) ]; then
  i=4
  while [ $i -ge 1 ]; do
    [ -f "$LOG.$i" ] && mv -f "$LOG.$i" "$LOG.$((i + 1))"
    i=$((i - 1))
  done
  mv -f "$LOG" "$LOG.1"
fi

FWDS_KEY_PASSPHRASE=$(load_secret "$ROOT" "$INST") || true
if [ -z "$FWDS_KEY_PASSPHRASE" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [run.sh] 取不到 $INST 的私钥口令" >>"$LOG"
  exit 1
fi
export FWDS_KEY_PASSPHRASE

cd "$ROOT" || exit 1
exec "$EXE" --config "$ROOT/config/$INST.ini" "$@" >>"$LOG" 2>&1
