# deploy/lib/common.sh：Linux / macOS 部署脚本共用的函数（设计 8.3、8.4 节）。
# 由 install.sh、upgrade.sh、rollback.sh 用 source 引入，不单独执行。
# 只用 bash 3.2 就有的写法（macOS 自带的 bash 是 3.2）。
#
# 安装目录（--root）的结构：
#   state/<实例>.current  该实例当前运行的版本号（一行文本）；启动器按它找程序，升级、回滚只改这个文件。
#                         每个实例各有一份：升级服务端不会顺带把同一台机器上的模拟设备也换掉
#   state/<实例>.previous 升级前的版本号，回滚时切回它
#   app/<版本>/           一个版本的完整程序包：bin/（程序和签名文件）、deploy/（脚本和配置模板）、VERSION
#   bin/run.sh            启动器：服务管理器（systemd / launchd）调用它，它取出口令再启动程序
#   config/<实例>.ini     运行配置，由安装脚本从模板生成；不含口令和私钥
#   pki/<实例>/           本实例的证书、加密的私钥、CA 根证书、CRL、许可证；pki/fsk.pub.pem 固件签名公钥
#   data/<实例>/          服务端的数据库和固件库，或设备的模拟 Flash（slot_a/、slot_b/、boot.json、outbox/）
#   secrets/<实例>.pass   私钥口令（仅 Linux；仅运行账户可读）。macOS 存在钥匙串里
#   logs/                 运行日志 <实例>.log（启动时超过 10 MB 就轮转，留 5 份）和安装、升级、回滚记录
#   backup/<时间>_<版本>_<实例>/  升级前的备份
#   run/<实例>.pid        不注册系统服务（--no-service）时的进程号
# “实例”是服务端的 server，或者设备的设备 ID：同一台机器上可以装一个服务端和多台模拟设备。

set -u
# 脚本新建的文件和目录（备份、记录、口令）只有运行账户能访问
umask 077

FWDS_LOG_FILE=""

say() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
  if [ -n "$FWDS_LOG_FILE" ]; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$FWDS_LOG_FILE"
  fi
}

die() {
  say "错误：$*"
  exit 1
}

# 本次操作的记录写到 logs/<动作>-<时间>-<实例>.log，供测试报告取证（FT-17、FT-20、FT-21）
start_record() {  # $1=root $2=动作 $3=实例
  mkdir -p "$1/logs"
  FWDS_LOG_FILE="$1/logs/$2-$(date -u +%Y%m%dT%H%M%SZ)-$3.log"
  : >"$FWDS_LOG_FILE"
  say "记录文件：$FWDS_LOG_FILE"
}

os_name() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo macos ;;
    *) echo other ;;
  esac
}

# 部署脚本自己所在的程序包：<包>/deploy/lib/common.sh → <包>
package_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

# 把相对路径换成绝对路径（文件必须存在）。后面的步骤会切换工作目录
abs_path() {
  [ -e "$1" ] || die "找不到 $1"
  echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
}

package_version() {  # $1=包目录
  [ -f "$1/VERSION" ] || die "$1 里没有 VERSION 文件，不是打包脚本生成的程序包"
  tr -d ' \r\n' <"$1/VERSION"
}

# ---------- 配置文件（ini） ----------

# 把 [section] 里 key 的值改成 value；没有这一项就加在该段末尾。
# 用 awk 逐行处理，不用 sed 替换，路径里的 / & 等字符不需要转义
ini_set() {  # $1=文件 $2=段 $3=键 $4=值
  local tmp="$1.tmp.$$"
  awk -v sec="$2" -v key="$3" -v val="$4" '
    function flush() { if (insec && !done) { print key "=" val; done = 1 } }
    /^\[.*\][ \t\r]*$/ {
      flush()
      name = $0; sub(/^\[/, "", name); sub(/\][ \t\r]*$/, "", name)
      insec = (name == sec)
      print; next
    }
    insec && index($0, key "=") == 1 { if (!done) { print key "=" val; done = 1 }; next }
    { print }
    END { flush(); if (!done) { print "[" sec "]"; print key "=" val } }
  ' "$1" >"$tmp" && mv "$tmp" "$1"
}

# 删掉整个 [section]（到下一个段头为止）。服务端的配置不需要 [client] 段，反之亦然
ini_drop_section() {  # $1=文件 $2=段
  local tmp="$1.tmp.$$"
  awk -v sec="$2" '
    /^\[.*\][ \t\r]*$/ { name = $0; sub(/^\[/, "", name); sub(/\][ \t\r]*$/, "", name); skip = (name == sec) }
    !skip { print }
  ' "$1" >"$tmp" && mv "$tmp" "$1"
}

ini_get() {  # $1=文件 $2=段 $3=键
  awk -v sec="$2" -v key="$3" '
    /^\[.*\][ \t\r]*$/ { name = $0; sub(/^\[/, "", name); sub(/\][ \t\r]*$/, "", name); insec = (name == sec); next }
    insec && index($0, key "=") == 1 { v = substr($0, length(key) + 2); sub(/\r$/, "", v); print v; exit }
  ' "$1"
}

# ---------- 私钥口令（设计 11.3 节“注入”） ----------
# 口令不进配置文件、不进命令行参数（ps 能看到参数）：
#   Linux：secrets/<实例>.pass，权限 600，只有运行账户能读；
#   macOS：当前用户的登录钥匙串，服务名 fwds-key-passphrase，账户名 <安装目录>:<实例>。

keychain_account() { echo "$1:$2"; }  # $1=root $2=实例

# 交互式读入口令（不回显）并保存，同时放进 FWDS_KEY_PASSPHRASE 供随后的 --check 使用
store_secret() {  # $1=root $2=实例
  local pass pass2
  if [ "$(os_name)" = macos ]; then
    # -w 放在最后且不跟值：由 security 自己提示输入（输两遍），口令不出现在命令行参数里（ps 看得到参数）
    security delete-generic-password -s fwds-key-passphrase -a "$(keychain_account "$1" "$2")" >/dev/null 2>&1 || true
    say "请输入 $2 的私钥口令（签发证书时设置的），存入登录钥匙串"
    security add-generic-password -s fwds-key-passphrase -a "$(keychain_account "$1" "$2")" \
      -l "FWDS $2 私钥口令" -w || die "写入钥匙串失败"
    pass=$(load_secret "$1" "$2")
    [ -n "$pass" ] || die "钥匙串里没有读到口令"
  else
    printf '%s 的私钥口令（签发证书时设置的，输入不回显）：' "$2" >&2
    IFS= read -r -s pass || die "没有读到口令"
    printf '\n再输入一遍：' >&2
    IFS= read -r -s pass2 || die "没有读到口令"
    printf '\n' >&2
    [ -n "$pass" ] || die "口令不能为空"
    [ "$pass" = "$pass2" ] || die "两次输入的口令不一致"
    mkdir -p "$1/secrets"
    chmod 700 "$1/secrets"
    ( umask 077 && printf '%s' "$pass" >"$1/secrets/$2.pass" )
  fi
  FWDS_KEY_PASSPHRASE="$pass"
  export FWDS_KEY_PASSPHRASE
}

# 取出口令打印到标准输出（由调用方用 $(...) 接住，不落盘、不进参数）
load_secret() {  # $1=root $2=实例
  case "$(os_name)" in
    macos) security find-generic-password -s fwds-key-passphrase -a "$(keychain_account "$1" "$2")" -w 2>/dev/null ;;
    *) [ -r "$1/secrets/$2.pass" ] && cat "$1/secrets/$2.pass" ;;
  esac
}

remove_secret() {  # $1=root $2=实例
  case "$(os_name)" in
    macos) security delete-generic-password -s fwds-key-passphrase -a "$(keychain_account "$1" "$2")" >/dev/null 2>&1 || true ;;
    *) rm -f "$1/secrets/$2.pass" ;;
  esac
}

# ---------- 程序 ----------

exe_path() {  # $1=root $2=版本 $3=角色
  echo "$1/app/$2/bin/fwds-$3"
}

current_file() { echo "$1/state/$2.current"; }    # $1=root $2=实例
previous_file() { echo "$1/state/$2.previous"; }
current_version() { [ -f "$(current_file "$1" "$2")" ] && tr -d ' \r\n' <"$(current_file "$1" "$2")"; }

# 原子地改写一行文本文件：先写临时文件再改名，中途断电不会留下半个文件
write_atomic() {  # $1=文件 $2=内容
  printf '%s\n' "$2" >"$1.tmp.$$" && mv "$1.tmp.$$" "$1"
}

# 用指定版本的程序跑一次 --check（部署自检，设计 8.4 节冒烟检查的一部分），输出“名称=值”。
# 口令从保存的地方取出，只放进这一条命令的环境
run_check() {  # $1=root $2=版本 $3=角色 $4=实例
  local exe pass
  exe=$(exe_path "$1" "$2" "$3")
  [ -x "$exe" ] || die "找不到程序 $exe"
  pass=$(load_secret "$1" "$4") || true
  [ -n "$pass" ] || die "取不到 $4 的私钥口令"
  ( cd "$1" && FWDS_KEY_PASSPHRASE="$pass" "$exe" --config "$1/config/$4.ini" --check 2>>"$1/logs/$4.check.log" )
}

# ---------- 服务（开机自启 + 进程守护，设计 8.3 节） ----------
#   Linux：systemd 系统服务 fwds-<实例>.service，Restart=always：进程无论怎么退出，5 秒后重新拉起；
#   macOS：launchd 用户代理 com.fwds.<实例>，RunAtLoad + KeepAlive：登录后启动，退出后 10 秒内拉起；
#   --no-service：不注册（云端测试用），直接在后台启动，没有守护。

service_mode() {  # 读安装时记下的方式
  cat "$1/run/$2.service" 2>/dev/null || echo none
}

systemd_unit_name() { echo "fwds-$1.service"; }
launchd_label() { echo "com.fwds.$1"; }

register_service() {  # $1=root $2=实例 $3=角色 $4=方式(systemd|launchd|none) $5=附加参数
  mkdir -p "$1/run"
  printf '%s\n' "$4" >"$1/run/$2.service"
  case "$4" in
    systemd)
      local unit user
      unit="/etc/systemd/system/$(systemd_unit_name "$2")"
      user="${SUDO_USER:-$(id -un)}"
      cat >"$unit" <<UNIT
# 由 deploy/install.sh 生成。卸载：systemctl disable --now $(systemd_unit_name "$2")
[Unit]
Description=FWDS $3 ($2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
WorkingDirectory=$1
ExecStart=/bin/bash $1/bin/run.sh $1 $2 $3 $5
# 进程守护：无论正常退出、崩溃还是被 kill，5 秒后重新拉起
Restart=always
RestartSec=5
# 停止时先发 SIGTERM，程序正常退出（写审计检查点、向服务端说 BYE）
KillSignal=SIGTERM
TimeoutStopSec=15

[Install]
# 开机自启
WantedBy=multi-user.target
UNIT
      systemctl daemon-reload || die "systemctl daemon-reload 失败"
      systemctl enable "$(systemd_unit_name "$2")" >/dev/null 2>&1 || die "systemctl enable 失败"
      say "已注册 systemd 服务 $(systemd_unit_name "$2")（开机自启，Restart=always）"
      ;;
    launchd)
      local plist label
      label=$(launchd_label "$2")
      plist="$HOME/Library/LaunchAgents/$label.plist"
      mkdir -p "$HOME/Library/LaunchAgents"
      local extra=""
      local a
      for a in $5; do extra="$extra    <string>$a</string>
"; done
      cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- 由 deploy/install.sh 生成。登录后自动启动（RunAtLoad），退出后自动拉起（KeepAlive） -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$1/bin/run.sh</string>
    <string>$1</string>
    <string>$2</string>
    <string>$3</string>
$extra  </array>
  <key>WorkingDirectory</key>
  <string>$1</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
PLIST
      say "已注册 launchd 用户代理 $label（$plist；登录后启动，KeepAlive 守护）"
      ;;
    none)
      printf '%s\n' "$5" >"$1/run/$2.args"
      say "按 --no-service 安装：没有注册开机自启和进程守护"
      ;;
  esac
}

start_service() {  # $1=root $2=实例 $3=角色
  case "$(service_mode "$1" "$2")" in
    systemd) systemctl start "$(systemd_unit_name "$2")" ;;
    launchd)
      launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$(launchd_label "$2").plist" 2>/dev/null ||
        launchctl kickstart "gui/$(id -u)/$(launchd_label "$2")"
      ;;
    *)
      # 没有服务管理器：在后台启动，记下进程号。exec 之后进程号就是程序本身
      local args
      args=$(cat "$1/run/$2.args" 2>/dev/null || true)
      # shellcheck disable=SC2086
      nohup /bin/bash "$1/bin/run.sh" "$1" "$2" "$3" $args >/dev/null 2>&1 &
      echo $! >"$1/run/$2.pid"
      ;;
  esac
}

stop_service() {  # $1=root $2=实例
  case "$(service_mode "$1" "$2")" in
    systemd) systemctl stop "$(systemd_unit_name "$2")" || true ;;
    launchd) launchctl bootout "gui/$(id -u)/$(launchd_label "$2")" 2>/dev/null || true ;;
    *)
      local pid
      pid=$(cat "$1/run/$2.pid" 2>/dev/null || true)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid"
        local i=0
        while kill -0 "$pid" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.5; i=$((i + 1)); done
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid"
      fi
      rm -f "$1/run/$2.pid"
      ;;
  esac
  say "已停止 $2"
}

# 进程是否在运行（冒烟检查用）
service_running() {  # $1=root $2=实例
  case "$(service_mode "$1" "$2")" in
    systemd) systemctl is-active --quiet "$(systemd_unit_name "$2")" ;;
    launchd) launchctl print "gui/$(id -u)/$(launchd_label "$2")" 2>/dev/null | grep -q "state = running" ;;
    *) local pid; pid=$(cat "$1/run/$2.pid" 2>/dev/null || true); [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null ;;
  esac
}

# ---------- 冒烟检查（设计 8.4 节） ----------

log_size() { [ -f "$1" ] && wc -c <"$1" | tr -d ' ' || echo 0; }

# 等日志里从 offset 字节起出现 pattern，最多等 timeout 秒
wait_log() {  # $1=日志 $2=offset $3=pattern $4=timeout
  local i=0
  while [ $i -lt "$4" ]; do
    if [ -f "$1" ] && tail -c +"$(($2 + 1))" "$1" | grep -q -- "$3"; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

# 启动后检查：进程起来了且 5 秒后还在；服务端在监听端口；（要求时）有设备登录成功 / 本设备登录成功
smoke_after_start() {  # $1=root $2=实例 $3=角色 $4=日志起点 $5=等登录的秒数（0 不等）
  local log="$1/logs/$2.log"
  wait_log "$log" "$4" "fwds.app] fwds-$3 " 20 || { say "冒烟检查失败：20 秒内没有看到程序启动"; return 1; }
  sleep 5
  service_running "$1" "$2" || { say "冒烟检查失败：程序启动后退出了，见 $log"; return 1; }
  if [ "$3" = server ]; then
    wait_log "$log" "$4" "listening on" 15 || { say "冒烟检查失败：服务端没有开始监听"; return 1; }
    say "冒烟检查：服务端已在监听"
  fi
  if [ "$5" -gt 0 ]; then
    wait_log "$log" "$4" "login ok" "$5" || { say "冒烟检查失败：$5 秒内没有设备登录成功"; return 1; }
    say "冒烟检查：设备登录成功"
  fi
  return 0
}

# ---------- 备份、恢复与回滚（设计 8.4 节） ----------

sha256_file() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# 备份项：配置、证书目录、固件签名公钥；服务端另有数据库和审计检查点。
# 固件库目录里的 .fwpkg 以包 ID 命名、只增不改，不备份文件本身；它们的索引（固件表）在数据库里。
# $4 是升级前用旧程序跑的 --check 输出，一起存下，回滚后拿来比对
make_backup() {  # $1=root $2=实例 $3=版本 $4=check 输出文件；打印备份目录
  local dir cfg db cp
  dir="$1/backup/$(date -u +%Y%m%dT%H%M%SZ)_$3_$2"
  mkdir -p "$dir/pki"
  cfg="$1/config/$2.ini"
  cp "$cfg" "$dir/config.ini"
  cp -R "$1/pki/$2" "$dir/pki/"
  cp "$1/pki/fsk.pub.pem" "$dir/pki/"
  cp "$4" "$dir/check-before.txt"
  printf 'version=%s\ninstance=%s\ntime=%s\n' "$3" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$dir/backup.txt"
  db=$(ini_get "$cfg" server db_file)
  if [ -n "$db" ]; then
    cp "$db" "$dir/fwds-server.db"
    printf 'db_sha256=%s\n' "$(sha256_file "$db")" >>"$dir/backup.txt"
    cp=$(ini_get "$cfg" server audit_checkpoint_file)
    [ -n "$cp" ] && [ -f "$cp" ] && cp "$cp" "$dir/audit-checkpoint"
  fi
  echo "$dir"
}

# 从备份恢复配置、证书和数据库。恢复前的数据库改名留着（不删），以便事后分析
restore_backup() {  # $1=root $2=实例 $3=备份目录
  local cfg db cp
  cfg="$1/config/$2.ini"
  cp "$3/config.ini" "$cfg"
  rm -rf "$1/pki/$2"
  cp -R "$3/pki/$2" "$1/pki/$2"
  cp "$3/pki/fsk.pub.pem" "$1/pki/fsk.pub.pem"
  db=$(ini_get "$cfg" server db_file)
  if [ -n "$db" ] && [ -f "$3/fwds-server.db" ]; then
    [ -f "$db" ] && mv "$db" "$db.before-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
    cp "$3/fwds-server.db" "$db"
    cp=$(ini_get "$cfg" server audit_checkpoint_file)
    [ -n "$cp" ] && [ -f "$3/audit-checkpoint" ] && cp "$3/audit-checkpoint" "$cp"
    local want got
    want=$(grep '^db_sha256=' "$3/backup.txt" | cut -d= -f2)
    got=$(sha256_file "$db")
    [ "$want" = "$got" ] || { say "恢复后的数据库和备份不一致"; return 1; }
    say "数据库已从备份恢复，SHA-256 与备份时一致（${got:0:8}…）"
  fi
  return 0
}

# 比较两份 --check 输出里的数据量（设备、固件、发布、审计日志条数）和审计哈希链结论
same_data() {  # $1=之前 $2=之后
  local k a b ok=0
  for k in devices firmware releases audit_rows audit_chain; do
    a=$(grep "^$k=" "$1" | cut -d= -f2)
    b=$(grep "^$k=" "$2" | cut -d= -f2)
    if [ "$a" != "$b" ]; then say "数据比对：$k 之前 $a，之后 $b"; ok=1; fi
  done
  return $ok
}

# 回滚到备份时的版本：停止 → 切回旧版本 → 恢复数据库和配置 → 旧程序自检 → 启动 → 冒烟检查
rollback_to() {  # $1=root $2=实例 $3=角色 $4=备份目录 $5=等登录的秒数
  local old after offset
  old=$(grep '^version=' "$4/backup.txt" | cut -d= -f2)
  [ -d "$1/app/$old" ] || { say "旧版本 $old 的程序已不在 $1/app 里"; return 1; }
  say "开始回滚到 $old（备份 $4）"
  stop_service "$1" "$2"
  write_atomic "$(current_file "$1" "$2")" "$old"
  restore_backup "$1" "$2" "$4" || return 1
  after="$1/run/$2.check"
  run_check "$1" "$old" "$3" "$2" >"$after" || { say "旧版本自检失败，见 $1/logs/$2.check.log"; return 1; }
  if [ "$3" = server ]; then
    same_data "$4/check-before.txt" "$after" || { say "回滚后的数据与升级前不一致"; return 1; }
    say "数据比对：设备、固件、发布、审计日志条数与升级前一致，审计哈希链完整"
  fi
  offset=$(log_size "$1/logs/$2.log")
  start_service "$1" "$2" "$3"
  smoke_after_start "$1" "$2" "$3" "$offset" "$5" || return 1
  rm -f "$(previous_file "$1" "$2")"
  say "回滚完成：当前版本 $old"
  return 0
}
