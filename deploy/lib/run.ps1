# 启动器（Windows）：计划任务 FWDS-<实例> 运行它；它负责启动程序并守护（设计 8.3 节，检查项 8-2、8-3）。
# 安装时复制到 <安装目录>\bin\run.ps1；它不随版本变，升级、回滚只改 state\<实例>.current。
# 循环：
#   1. 有停止标记 run\<实例>.stop 就退出（升级、回滚脚本停止程序时放这个标记）；
#   2. 按 state\<实例>.current 找到当前版本的程序；日志轮转（logs\<实例>.log → .1 → … → .5）；
#   3. 用 DPAPI 解出私钥口令，放进环境变量 FWDS_KEY_PASSPHRASE，启动程序后立即从自己的环境里删掉
#      （程序读取后也会清除自己环境里的这一项）；
#   4. 等程序退出；无论怎么退出（崩溃、被任务管理器结束），5 秒后回到第 1 步重新启动。
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$Instance,
  [Parameter(Mandatory = $true)][ValidateSet('server', 'client')][string]$Role,
  [switch]$Headless
)
. "$Root\bin\common.ps1"
$ErrorActionPreference = 'Continue'   # 启动器不能因为一次失败就退出，否则就没有守护了

$log = "$Root\logs\$Instance.log"
$runLog = "$Root\logs\$Instance.run.log"
$stopFlag = "$Root\run\$Instance.stop"
function Write-Run([string]$Text) {
  Add-Content -LiteralPath $runLog -Value ("{0} {1}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Text) -Encoding UTF8
}

while (-not (Test-Path -LiteralPath $stopFlag)) {
  $version = Get-CurrentVersion $Root $Instance
  $exe = Get-ExePath $Root $version $Role
  for ($i = 4; $i -ge 1; $i--) {
    if (Test-Path -LiteralPath "$log.$i") { Move-Item -LiteralPath "$log.$i" -Destination "$log.$($i + 1)" -Force }
  }
  if (Test-Path -LiteralPath $log) { Move-Item -LiteralPath $log -Destination "$log.1" -Force }

  $secret = Get-Secret $Root $Instance
  if (-not $secret -or -not (Test-Path -LiteralPath $exe)) {
    Write-Run "取不到口令或找不到程序 $exe，60 秒后重试"
    Start-Sleep -Seconds 60
    continue
  }
  $arguments = @('--config', "`"$Root\config\$Instance.ini`"")
  if ($Headless) { $arguments += '--headless' }
  $env:FWDS_KEY_PASSPHRASE = $secret
  try {
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $Root -NoNewWindow -PassThru `
         -RedirectStandardError $log
  } finally {
    Remove-Item Env:FWDS_KEY_PASSPHRASE -ErrorAction SilentlyContinue
    $secret = $null
  }
  $null = $p.Handle   # 先取一次句柄，否则 Windows PowerShell 5.1 在进程退出后读不到退出码
  Set-Content -LiteralPath "$Root\run\$Instance.pid" -Value $p.Id -Encoding ASCII
  Write-Run "已启动 $exe（进程 $($p.Id)）"
  $p.WaitForExit()
  Write-Run "进程 $($p.Id) 退出，退出码 $($p.ExitCode)"
  if (Test-Path -LiteralPath $stopFlag) { break }
  Start-Sleep -Seconds 5
}
Write-Run '收到停止标记，启动器退出'
