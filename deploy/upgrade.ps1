# deploy\upgrade.ps1：把已安装的服务端或设备客户端升级到本程序包的版本（设计 8.4 节，检查项 1-8、8-4，FT-20）。
# 在新版本的程序包里运行：
#   powershell -ExecutionPolicy Bypass -File deploy\upgrade.ps1 -Root C:\fwds -Instance server [-ExpectLogin 60]
#   powershell -ExecutionPolicy Bypass -File deploy\upgrade.ps1 -Root C:\fwds -Instance DEV-001
# 步骤与 deploy/upgrade.sh 相同；切换版本之后任何一步失败都自动回滚。
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Instance,
  [int]$ExpectLogin = -1
)
. "$PSScriptRoot\lib\common.ps1"

$Root = (Resolve-Path $Root).Path
if (-not (Test-Path -LiteralPath "$Root\config\$Instance.ini")) { Stop-WithError "$Root 里没有装 $Instance" }
$Role = if ($Instance -eq 'server') { 'server' } else { 'client' }
if ($ExpectLogin -lt 0) { $ExpectLogin = if ($Role -eq 'server') { 0 } else { 60 } }
$Package = Get-PackageRoot
$New = Get-PackageVersion $Package
$Old = Get-CurrentVersion $Root $Instance
if ($New -eq $Old) { Stop-WithError "已经是 $New，不需要升级" }
Start-Record $Root 'upgrade' $Instance
Write-Step "升级 ${Instance}：$Old → $New"
if ((Invoke-Program "$Package\bin\fwds-$Role.exe" @('--version') $Package $null).ExitCode -ne 0) {
  Stop-WithError '新版本的程序运行不起来（缺运行库？）'
}

# 1. 停止。服务端重启后进行中的发布一律恢复为“已暂停”
Stop-Fwds $Root $Instance

# 2. 旧程序自检，记下升级前的数据量
$before = Invoke-Check $Root $Old $Role $Instance ''
if ($before.ExitCode -ne 0) {
  Start-Fwds $Root $Instance $Role
  Stop-WithError "旧版本自检就没通过（见 $Root\logs\$Instance.check.log），先排查再升级；已重新启动旧版本"
}
Write-Step "升级前：$($before.Output -join ' ')"

# 3. 备份
$backup = New-Backup $Root $Instance $Old $before.Output
Write-Step "已备份到 $backup"

function Stop-AndRollback([string]$Reason) {
  Write-Step "升级失败：$Reason。自动回滚"
  if (Invoke-Rollback $Root $Instance $Role $backup $ExpectLogin) { Stop-WithError "升级失败，已回滚到 $Old" }
  Stop-WithError '升级失败，自动回滚也失败了：按 deploy\README.md 的“手工回滚”处理'
}

# 4. 新版本装入 app\<版本>\，切换本实例的 current
if (-not (Test-Path -LiteralPath "$Root\app\$New")) {
  New-Item -ItemType Directory -Force -Path "$Root\app\$New" | Out-Null
  Copy-Item -Path "$Package\bin", "$Package\deploy", "$Package\VERSION" -Destination "$Root\app\$New" -Recurse
}
Write-Atomic (Get-PreviousFile $Root $Instance) $Old
Write-Atomic (Get-CurrentFile $Root $Instance) $New
Write-Step "当前版本已切换为 $New"

# 5. 新程序自检（服务端在这一步迁移数据库），比对数据量
$after = Invoke-Check $Root $New $Role $Instance ''
if ($after.ExitCode -ne 0) { Stop-AndRollback "新版本自检失败（见 $Root\logs\$Instance.check.log）" }
Write-Step "升级后：$($after.Output -join ' ')"
if ($Role -eq 'server') {
  if (-not (Test-SameData $before.Output $after.Output)) { Stop-AndRollback '迁移后的数据与升级前不一致' }
  Write-Step '数据比对：设备、固件、发布、审计日志条数与升级前一致，审计哈希链完整'
}

# 6. 启动并做冒烟检查
$since = Get-Date
Start-Fwds $Root $Instance $Role
if (-not (Test-Smoke $Root $Instance $Role $since $ExpectLogin)) { Stop-AndRollback '冒烟检查没有通过' }
Write-Step "升级完成：$Instance 当前版本 $New。需要退回时运行 deploy\rollback.ps1 -Root $Root -Instance $Instance"
