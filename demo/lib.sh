# 演示脚本的公共部分，由 setup.sh、start.sh、stop.sh、reset.sh、tamper_audit.sh 引入。
# 所有演示文件都在仓库的 local/demo/ 下（local/ 已在 .gitignore 中，不会进仓库）。

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"                      # 配置里的相对路径都相对于仓库根目录

BIN=${FWDS_BIN:-build/dev/bin}  # 程序所在目录，可用环境变量 FWDS_BIN 改
D=local/demo                    # 演示工作目录
PORT=${DEMO_PORT:-19443}        # 服务端端口
SLOW_PORT=${DEMO_SLOW_PORT:-19444}   # 慢速链路代理端口（DEV-002 经它连接）
SLOW_RATE=${DEMO_SLOW_RATE:-2000000} # 慢速链路速率，字节/秒
MODEL=PLC-X200
# setup.sh 之后以生成的配置为准，start.sh 不用再设一遍环境变量（重新 setup 时可用 DEMO_PORT 换端口）
if [ -z "${DEMO_PORT:-}" ] && [ -f "$D/conf/server.ini" ]; then
  PORT=$(awk -F= '$1 == "listen_port" { print $2; exit }' "$D/conf/server.ini")
  SLOW_PORT=$(awk -F= '$1 == "server_port" { print $2; exit }' "$D/conf/DEV-002.ini")
fi

# 演示设备：ID、分组、是否显示界面、连哪个端口
#   DEV-001  单台升级、坏固件回滚、断网补传      界面
#   DEV-002  灰度发布的金丝雀，经慢速链路下载    界面
#   DEV-003  灰度发布的全量批                    无界面
#   DEV-004  灰度发布的全量批                    无界面
DEVICES=(DEV-001 DEV-002 DEV-003 DEV-004)
group_of() { case $1 in DEV-002) echo canary ;; *) echo line-A ;; esac; }
has_ui() { case $1 in DEV-001 | DEV-002) return 0 ;; *) return 1 ;; esac; }
port_of() { case $1 in DEV-002) echo "$SLOW_PORT" ;; *) echo "$PORT" ;; esac; }

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m注意：\033[0m%s\n' "$*" >&2; }
die() {
  printf '\033[1;31m失败：\033[0m%s\n' "$*" >&2
  exit 1
}

need_bins() {
  for p in fwds-signer fwds-server fwds-client fwds-demo-seed; do
    [ -x "$BIN/$p" ] || die "没有 $BIN/$p。先构建：cmake --preset dev -G Ninja && cmake --build --preset dev"
  done
}

# 不回显地读一个口令，存进名为 $1 的变量。$2 是提示，$3 是最短长度，$4 非空时要求输入两遍
read_secret() {
  local __name=$1 prompt=$2 min=$3 twice=${4:-} a b
  while :; do
    read -r -s -p "$prompt" a
    echo
    if [ "${#a}" -lt "$min" ]; then
      warn "至少 $min 个字符"
      continue
    fi
    if [ -n "$twice" ]; then
      read -r -s -p "再输入一遍：" b
      echo
      [ "$a" = "$b" ] || {
        warn "两次输入不一致"
        continue
      }
    fi
    break
  done
  printf -v "$__name" '%s' "$a"
}

pid_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

# 停掉 run/ 下记录的全部进程：先 TERM（服务端借此写审计检查点），5 秒后仍在的再 KILL
stop_all() {
  local f any=0
  for f in "$D"/run/*.pid; do
    [ -e "$f" ] || continue
    if pid_alive "$f"; then
      kill -TERM "$(cat "$f")" 2>/dev/null || true
      any=1
    fi
  done
  if [ "$any" = 1 ]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      any=0
      for f in "$D"/run/*.pid; do
        [ -e "$f" ] || continue
        pid_alive "$f" && any=1
      done
      [ "$any" = 0 ] && break
      sleep 0.5
    done
    for f in "$D"/run/*.pid; do
      [ -e "$f" ] || continue
      pid_alive "$f" && kill -KILL "$(cat "$f")" 2>/dev/null || true
    done
  fi
  rm -f "$D"/run/*.pid
}
