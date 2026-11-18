# deploy\rollback.ps1：把服务端或设备客户端退回升级前的版本（设计 8.4 节，检查项 1-8、8-4，FT-21）。
#   powershell -ExecutionPolicy Bypass -File deploy\rollback.ps1 -Root C:\fwds -Instance server [-Backup <备份目录>] [-ExpectLogin 60]
# 默认用 state\<实例>.previous 记录的版本和该版本最新的一份备份。步骤与 deploy/rollback.sh 相同。
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Instance,
  [string]$Backup,
  [int]$ExpectLogin = -1
)
. "$PSScriptRoot\lib\common.ps1"

$Root = (Resolve-Path $Root).Path
if (-not (Test-Path -LiteralPath "$Root\config\$Instance.ini")) { Stop-WithError "$Root 里没有装 $Instance" }
$Role = if ($Instance -eq 'server') { 'server' } else { 'client' }
if ($ExpectLogin -lt 0) { $ExpectLogin = if ($Role -eq 'server') { 0 } else { 60 } }
Start-Record $Root 'rollback' $Instance

if (-not $Backup) {
  $prevFile = Get-PreviousFile $Root $Instance
  if (-not (Test-Path -LiteralPath $prevFile)) { Stop-WithError '没有 previous 记录（没升级过，或已经回滚过）；可以用 -Backup 指定备份目录' }
  $prev = (Get-Content -LiteralPath $prevFile -Raw).Trim()
  # 备份目录名以 UTC 时间开头，按名字排序最后一个就是最新的
  $found = Get-ChildItem -LiteralPath "$Root\backup" -Directory | Where-Object { $_.Name -like "*_$($prev)_$Instance" } |
           Sort-Object Name | Select-Object -Last 1
  if (-not $found) { Stop-WithError "找不到 $Instance 版本 $prev 的备份" }
  $Backup = $found.FullName
}
if (-not (Test-Path -LiteralPath "$Backup\backup.txt")) { Stop-WithError "$Backup 不是备份目录" }
Write-Step "回滚 ${Instance}：当前 $(Get-CurrentVersion $Root $Instance)，目标 $(Get-KeyValue (Read-Lines "$Backup\backup.txt") 'version')"
if (-not (Invoke-Rollback $Root $Instance $Role $Backup $ExpectLogin)) { Stop-WithError '回滚失败，见上面的记录' }
