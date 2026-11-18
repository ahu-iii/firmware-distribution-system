#!/usr/bin/env bash
# 停止演示的全部进程（服务端、设备、代理）。数据保留，demo/start.sh 可以接着演示。
#   demo/stop.sh            全部停止
#   demo/stop.sh DEV-001    只停一台设备
source "$(dirname "$0")/lib.sh"

if [ $# -gt 0 ]; then
  for name in "$@"; do
    f="$D/run/$name.pid"
    if pid_alive "$f"; then
      kill -TERM "$(cat "$f")"
      # 等它真正退出（服务端要写审计检查点、释放端口），最多 5 秒，之后强制结束
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        pid_alive "$f" || break
        sleep 0.5
      done
      pid_alive "$f" && kill -KILL "$(cat "$f")" 2>/dev/null || true
      echo "  已停止 $name"
    fi
    rm -f "$f"
  done
  exit 0
fi
stop_all
say "已全部停止"
