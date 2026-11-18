#!/usr/bin/env bash
# 启动演示：服务端、慢速链路代理、四台设备，全部在后台运行，终端随即回到提示符。
#   demo/start.sh            启动全部（已在运行的进程跳过，所以也可以用来补起被停掉的服务端）
#   demo/start.sh DEV-001    只（重新）启动一台设备，例如演示“立即断电”之后把它开回来
# 只问一次演示密钥口令，分别交给每个进程（各自读取后从环境中清除）。
# 每个进程的输出在 local/demo/logs/<名字>.out，进程号在 local/demo/run/<名字>.pid。
source "$(dirname "$0")/lib.sh"

need_bins
[ -f "$D/conf/server.ini" ] || die "还没有准备演示环境，先运行 demo/setup.sh"
command -v python3 >/dev/null || die "没有 python3（慢速链路代理要用）。macOS 上运行 xcode-select --install"

# 后台启动一个进程，记下进程号。$1 是名字，其余是命令
launch() {
  local name=$1
  shift
  if pid_alive "$D/run/$name.pid"; then
    echo "  $name 已在运行（进程 $(cat "$D/run/$name.pid")）"
    return
  fi
  nohup "$@" >"$D/logs/$name.out" 2>&1 </dev/null &
  echo $! >"$D/run/$name.pid"
  echo "  $name 已启动（进程 $!）"
}

start_device() {
  local dev=$1 args=(--config "$D/conf/$dev.ini")
  has_ui "$dev" || args+=(--headless)
  FWDS_KEY_PASSPHRASE=$KEYPASS launch "$dev" "$BIN/fwds-client" "${args[@]}"
}

read_secret KEYPASS "演示密钥口令：" 1

if [ $# -gt 0 ]; then
  for dev in "$@"; do start_device "$dev"; done
  exit 0
fi

# 端口被占用而对应的进程又不是本脚本启动的，多半是上一次没停干净
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if ! pid_alive "$D/run/server.pid" && port_busy "$PORT"; then
  die "端口 $PORT 已被占用。先运行 demo/stop.sh；还不行就换端口重新准备：DEMO_PORT=19543 DEMO_SLOW_PORT=19544 demo/setup.sh"
fi
if ! pid_alive "$D/run/slow-proxy.pid" && port_busy "$SLOW_PORT"; then
  die "端口 $SLOW_PORT 已被占用。先运行 demo/stop.sh"
fi

say "启动服务端"
FWDS_KEY_PASSPHRASE=$KEYPASS launch server "$BIN/fwds-server" --config "$D/conf/server.ini"
# 等服务端开始监听（最多 15 秒），失败时直接给出日志尾部
for _ in $(seq 1 30); do
  port_busy "$PORT" && break
  pid_alive "$D/run/server.pid" || {
    tail -n 20 "$D/logs/server.out" >&2
    die "服务端没有起来，日志见 $D/logs/server.out"
  }
  sleep 0.5
done

say "启动慢速链路代理（DEV-002 经它连接，$SLOW_RATE 字节/秒）"
launch slow-proxy python3 tests/attack_tools/tls_proxy.py "$SLOW_PORT" "$PORT" slow "$SLOW_RATE"

say "启动设备"
for dev in "${DEVICES[@]}"; do start_device "$dev"; done
unset KEYPASS

cat <<EOF
全部在后台运行。服务端窗口里用维护员 maint01 登录；设备 DEV-001、DEV-002 有窗口，DEV-003、DEV-004 无窗口。
窗口没出现时用 Cmd-Tab（macOS）切过去。停止：demo/stop.sh；回到演示前的状态：demo/reset.sh。
EOF
