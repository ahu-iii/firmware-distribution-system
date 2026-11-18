#!/usr/bin/env bash
# 演示审计日志防篡改：绕过程序，直接用 sqlite3 改数据库里的一条审计日志，
# 然后由审计员在“审计日志”页点“校验日志完整性”，程序指出被改的是第几条。
#   demo/tamper_audit.sh          把最近一条发布类（ROLLOUT）记录的操作者改成 intruder，没有下发记录时改中间一条
#   demo/tamper_audit.sh delete   删除同一条
# 演示完用 demo/reset.sh 恢复。
source "$(dirname "$0")/lib.sh"

DB=$D/data/fwds-server.db
command -v sqlite3 >/dev/null || die "没有 sqlite3 命令（macOS 自带；Linux 上 apt install sqlite3）"
[ -f "$DB" ] || die "没有数据库 $DB，先运行 demo/setup.sh"

total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM audit_log")
id=$(sqlite3 "$DB" "SELECT COALESCE(MAX(id), 0) FROM audit_log WHERE category = 'ROLLOUT'")
[ "$id" -ge 1 ] || id=$((total / 2))
[ "$id" -ge 1 ] || die "审计日志太少"
[ "$id" -lt "$total" ] || id=$((total - 1))   # 不选最后一条：删最后一条要靠检查点发现，讲起来绕
echo "审计日志共 $total 条，改第 $id 条。改之前："
sqlite3 -header -column "$DB" "SELECT id, ts, category, actor, message FROM audit_log WHERE id = $id"

if [ "${1:-}" = delete ]; then
  sqlite3 "$DB" "DELETE FROM audit_log WHERE id = $id"
  say "已删除第 $id 条。预期校验结果：第 $((id + 1)) 条之前缺少记录（期望序号 $id）"
else
  sqlite3 "$DB" "UPDATE audit_log SET actor = 'intruder' WHERE id = $id"
  echo "改之后："
  sqlite3 -header -column "$DB" "SELECT id, ts, category, actor, message FROM audit_log WHERE id = $id"
  say "已把第 $id 条的操作者改成 intruder。预期校验结果：第 $id 条的内容与它的哈希不符"
fi
echo "现在用审计员 audit01 在“审计日志”页点“校验日志完整性”。"
