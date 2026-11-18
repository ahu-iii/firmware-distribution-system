#!/bin/bash
# deploy/upgrade.sh：把已安装的服务端或设备客户端升级到本程序包的版本（设计 8.4 节，检查项 1-8、8-4，FT-20）。
# 在新版本的程序包里运行：
#   deploy/upgrade.sh --root /opt/fwds --instance server [--expect-login 60]
#   deploy/upgrade.sh --root /opt/fwds --instance DEV-001
# 选项：
#   --expect-login N   冒烟检查时等 N 秒，要看到设备登录成功。服务端默认 0（不等），设备默认 60
#
# 只升级 --instance 指定的这一个实例；同一台机器上的其他实例（例如模拟设备）不受影响。
# 步骤：停止程序（服务端重启后进行中的发布自动恢复为“已暂停”）→ 旧程序自检并记下数据量 → 备份
#       → 新版本装入 app/<版本>/ → 切换 current → 新程序自检（数据库在这一步迁移）并比对数据量
#       → 启动 → 冒烟检查（进程存活、端口监听、设备登录）。
# 切换之后任何一步失败都自动回滚（同 deploy/rollback.sh），脚本以非零状态退出。
set -u
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ROOT="" INST="" EXPECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT=$2; shift 2 ;;
    --instance) INST=$2; shift 2 ;;
    --expect-login) EXPECT=$2; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "不认识的参数 $1" ;;
  esac
done
[ -n "$ROOT" ] && [ -n "$INST" ] || die "缺少 --root 或 --instance"
ROOT=$(cd "$ROOT" && pwd) || die "没有 $ROOT"
[ -f "$ROOT/config/$INST.ini" ] || die "$ROOT 里没有装 $INST"
ROLE=$([ "$INST" = server ] && echo server || echo client)
EXPECT=${EXPECT:-$([ "$ROLE" = server ] && echo 0 || echo 60)}
PKG=$(package_root)
NEW=$(package_version "$PKG")
OLD=$(current_version "$ROOT" "$INST")
[ "$NEW" != "$OLD" ] || die "已经是 $NEW，不需要升级"
start_record "$ROOT" upgrade "$INST"
say "升级 $INST：$OLD → $NEW"
"$PKG/bin/fwds-$ROLE" --version >/dev/null 2>&1 || die "新版本的程序运行不起来（缺运行库？）"

# 1. 停止。服务端停止前不必手工暂停发布：重启后进行中的发布一律恢复为“已暂停”，要操作员确认后才继续
stop_service "$ROOT" "$INST"

# 2. 旧程序自检，记下升级前的数据量
BEFORE="$ROOT/run/$INST.check-before"
if ! run_check "$ROOT" "$OLD" "$ROLE" "$INST" >"$BEFORE"; then
  start_service "$ROOT" "$INST" "$ROLE"
  die "旧版本自检就没通过（见 $ROOT/logs/$INST.check.log），先排查再升级；已重新启动旧版本"
fi
say "升级前：$(tr '\n' ' ' <"$BEFORE")"

# 3. 备份
BACKUP=$(make_backup "$ROOT" "$INST" "$OLD" "$BEFORE")
say "已备份到 $BACKUP"

fail_and_rollback() {
  say "升级失败：$1。自动回滚"
  if rollback_to "$ROOT" "$INST" "$ROLE" "$BACKUP" "$EXPECT"; then
    die "升级失败，已回滚到 $OLD"
  fi
  die "升级失败，自动回滚也失败了：按 deploy/README.md 的“手工回滚”处理"
}

# 4. 新版本装入 app/<版本>/，切换本实例的 current
if [ ! -d "$ROOT/app/$NEW" ]; then
  mkdir -p "$ROOT/app/$NEW"
  cp -R "$PKG/bin" "$PKG/deploy" "$PKG/VERSION" "$ROOT/app/$NEW/"
fi
write_atomic "$(previous_file "$ROOT" "$INST")" "$OLD"
write_atomic "$(current_file "$ROOT" "$INST")" "$NEW"
say "当前版本已切换为 $NEW"

# 5. 新程序自检：服务端打开数据库时把表结构迁移到新版本，然后比对数据量
AFTER="$ROOT/run/$INST.check"
run_check "$ROOT" "$NEW" "$ROLE" "$INST" >"$AFTER" || fail_and_rollback "新版本自检失败（见 $ROOT/logs/$INST.check.log）"
say "升级后：$(tr '\n' ' ' <"$AFTER")"
if [ "$ROLE" = server ]; then
  same_data "$BEFORE" "$AFTER" || fail_and_rollback "迁移后的数据与升级前不一致"
  say "数据比对：设备、固件、发布、审计日志条数与升级前一致，审计哈希链完整"
fi

# 6. 启动并做冒烟检查
OFFSET=$(log_size "$ROOT/logs/$INST.log")
start_service "$ROOT" "$INST" "$ROLE"
smoke_after_start "$ROOT" "$INST" "$ROLE" "$OFFSET" "$EXPECT" || fail_and_rollback "冒烟检查没有通过"
say "升级完成：$INST 当前版本 $NEW。需要退回时运行 deploy/rollback.sh --root $ROOT --instance $INST"
