# deploy\lib\common.ps1：Windows 部署脚本共用的函数（设计 8.3、8.4 节）。
# 由 install.ps1、upgrade.ps1、rollback.ps1 和启动器 run.ps1 用点号引入，不单独执行。
# Windows PowerShell 5.1 和 PowerShell 7 都能用。
#
# 安装目录（-Root）的结构和 Linux / macOS 相同（见 deploy/lib/common.sh 开头），区别：
#   secrets\<实例>.dpapi   私钥口令，用 Windows DPAPI 按当前用户加密（ConvertFrom-SecureString），
#                          只有安装它的那个 Windows 账户能解开；文件拷到别的账户或别的机器上解不开
#   run\<实例>.pid         启动器启动的程序进程号；run\<实例>.stop 存在时启动器不再拉起程序
#   logs\<实例>.log        每次启动换一个新文件，旧的依次改名为 .1 ~ .5（保留最近 5 次）
# 开机自启和守护：任务计划程序里的任务 FWDS-<实例>，当前用户登录时触发，运行启动器 run.ps1；
# run.ps1 自己循环：程序退出 5 秒后重新启动（进程守护）。任务本身也设置了失败后每 1 分钟重试。

$ErrorActionPreference = 'Stop'
$script:FwdsLogFile = $null

function Write-Step([string]$Message) {
  $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Message
  Write-Host $line
  if ($script:FwdsLogFile) { Add-Content -LiteralPath $script:FwdsLogFile -Value $line -Encoding UTF8 }
}

function Stop-WithError([string]$Message) {
  Write-Step "错误：$Message"
  exit 1
}

# 本次操作的记录写到 logs\<动作>-<时间>-<实例>.log，供测试报告取证（FT-17、FT-20、FT-21）
function Start-Record([string]$Root, [string]$Action, [string]$Instance) {
  New-Item -ItemType Directory -Force -Path "$Root\logs" | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $script:FwdsLogFile = "$Root\logs\$Action-$stamp-$Instance.log"
  Set-Content -LiteralPath $script:FwdsLogFile -Value '' -Encoding UTF8
  Write-Step "记录文件：$script:FwdsLogFile"
}

# 部署脚本所在的程序包：<包>\deploy\lib\common.ps1 → <包>
function Get-PackageRoot { (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path }

function Get-PackageVersion([string]$Package) {
  $file = Join-Path $Package 'VERSION'
  if (-not (Test-Path -LiteralPath $file)) { Stop-WithError "$Package 里没有 VERSION 文件，不是打包脚本生成的程序包" }
  (Get-Content -LiteralPath $file -Raw).Trim()
}

# ---------- 配置文件（ini） ----------

function Read-Lines([string]$File) { @(Get-Content -LiteralPath $File -Encoding UTF8) }
function Write-Lines([string]$File, $Lines) {
  # 不带 BOM 的 UTF-8：Qt 的 QSettings 不认 BOM
  [IO.File]::WriteAllLines($File, [string[]]$Lines, (New-Object Text.UTF8Encoding($false)))
}
function Get-SectionName([string]$Line) {
  if ($Line -match '^\[(.+)\]\s*$') { return $Matches[1] }
  return $null
}

# 把 [Section] 里 Key 的值改成 Value；没有这一项就加在该段末尾
function Set-IniValue([string]$File, [string]$Section, [string]$Key, [string]$Value) {
  $out = New-Object Collections.Generic.List[string]
  $inSection = $false; $done = $false
  foreach ($line in (Read-Lines $File)) {
    $name = Get-SectionName $line
    if ($null -ne $name) {
      if ($inSection -and -not $done) { $out.Add("$Key=$Value"); $done = $true }
      $inSection = ($name -eq $Section)
      $out.Add($line); continue
    }
    if ($inSection -and $line.StartsWith("$Key=")) {
      if (-not $done) { $out.Add("$Key=$Value"); $done = $true }
      continue
    }
    $out.Add($line)
  }
  if (-not $done) {
    if (-not $inSection) { $out.Add("[$Section]") }
    $out.Add("$Key=$Value")
  }
  Write-Lines $File $out
}

function Get-IniValue([string]$File, [string]$Section, [string]$Key) {
  $inSection = $false
  foreach ($line in (Read-Lines $File)) {
    $name = Get-SectionName $line
    if ($null -ne $name) { $inSection = ($name -eq $Section); continue }
    if ($inSection -and $line.StartsWith("$Key=")) { return $line.Substring($Key.Length + 1).Trim() }
  }
  return ''
}

# 删掉整个 [Section]。服务端的配置不需要 [client] 段，反之亦然
function Remove-IniSection([string]$File, [string]$Section) {
  $out = New-Object Collections.Generic.List[string]
  $skip = $false
  foreach ($line in (Read-Lines $File)) {
    $name = Get-SectionName $line
    if ($null -ne $name) { $skip = ($name -eq $Section) }
    if (-not $skip) { $out.Add($line) }
  }
  Write-Lines $File $out
}

# ---------- 私钥口令（设计 11.3 节“注入”）：DPAPI 加密保存 ----------

function Get-SecretFile([string]$Root, [string]$Instance) { "$Root\secrets\$Instance.dpapi" }

# 交互式读入口令（不回显），用 DPAPI 加密后保存；返回明文供随后的自检使用
function Save-Secret([string]$Root, [string]$Instance) {
  $first = Read-Host "$Instance 的私钥口令（签发证书时设置的）" -AsSecureString
  $second = Read-Host "再输入一遍" -AsSecureString
  $a = [Net.NetworkCredential]::new('', $first).Password
  $b = [Net.NetworkCredential]::new('', $second).Password
  if ([string]::IsNullOrEmpty($a)) { Stop-WithError '口令不能为空' }
  if ($a -ne $b) { Stop-WithError '两次输入的口令不一致' }
  New-Item -ItemType Directory -Force -Path "$Root\secrets" | Out-Null
  # 不带 -Key 时 ConvertFrom-SecureString 用 DPAPI（当前用户）加密
  ConvertFrom-SecureString -SecureString $first | Set-Content -LiteralPath (Get-SecretFile $Root $Instance) -Encoding ASCII
  return $a
}

function Get-Secret([string]$Root, [string]$Instance) {
  $file = Get-SecretFile $Root $Instance
  if (-not (Test-Path -LiteralPath $file)) { return '' }
  $secure = Get-Content -LiteralPath $file -Raw | ForEach-Object { $_.Trim() } | ConvertTo-SecureString
  return [Net.NetworkCredential]::new('', $secure).Password
}

# 安装目录只给当前用户、SYSTEM 和管理员访问（去掉继承来的 Users 读权限）
function Protect-Directory([string]$Path) {
  $user = "$env:USERDOMAIN\$env:USERNAME"
  & icacls.exe $Path /inheritance:r /grant:r "${user}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Step "警告：设置 $Path 的访问权限失败" }
}

# ---------- 版本 ----------

function Get-CurrentFile([string]$Root, [string]$Instance) { "$Root\state\$Instance.current" }
function Get-PreviousFile([string]$Root, [string]$Instance) { "$Root\state\$Instance.previous" }
function Get-CurrentVersion([string]$Root, [string]$Instance) {
  $file = Get-CurrentFile $Root $Instance
  if (Test-Path -LiteralPath $file) { return (Get-Content -LiteralPath $file -Raw).Trim() }
  return ''
}
# 先写临时文件再改名：中途断电不会留下半个文件
function Write-Atomic([string]$File, [string]$Text) {
  $tmp = "$File.tmp"
  Set-Content -LiteralPath $tmp -Value $Text -Encoding ASCII
  Move-Item -LiteralPath $tmp -Destination $File -Force
}
function Get-ExePath([string]$Root, [string]$Version, [string]$Role) { "$Root\app\$Version\bin\fwds-$Role.exe" }

# 运行一个程序并等它结束，标准输出返回给调用方，标准错误追加到 ErrLog。
# 用 Start-Process 而不是 & 调用：Windows PowerShell 5.1 会把原生程序的标准错误当成异常
function Invoke-Program([string]$Exe, [string[]]$Arguments, [string]$WorkDir, [string]$ErrLog) {
  $outFile = [IO.Path]::GetTempFileName(); $errFile = [IO.Path]::GetTempFileName()
  try {
    $quoted = $Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -WorkingDirectory $WorkDir -NoNewWindow -Wait -PassThru `
         -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    if ($ErrLog) { Get-Content -LiteralPath $errFile -Encoding UTF8 | Add-Content -LiteralPath $ErrLog -Encoding UTF8 }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = @(Get-Content -LiteralPath $outFile -Encoding UTF8) }
  } finally {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
  }
}

# 部署自检（--check）：口令只放进这一次运行的环境变量，程序读取后清除
function Invoke-Check([string]$Root, [string]$Version, [string]$Role, [string]$Instance, [string]$Secret) {
  $exe = Get-ExePath $Root $Version $Role
  if (-not (Test-Path -LiteralPath $exe)) { Stop-WithError "找不到程序 $exe" }
  if (-not $Secret) { $Secret = Get-Secret $Root $Instance }
  if (-not $Secret) { Stop-WithError "取不到 $Instance 的私钥口令" }
  $env:FWDS_KEY_PASSPHRASE = $Secret
  try {
    return Invoke-Program $exe @('--config', "$Root\config\$Instance.ini", '--check') $Root "$Root\logs\$Instance.check.log"
  } finally {
    Remove-Item Env:FWDS_KEY_PASSPHRASE -ErrorAction SilentlyContinue
  }
}

# ---------- 开机自启与守护（任务计划程序） ----------

function Get-TaskName([string]$Instance) { "FWDS-$Instance" }
function Get-ServiceMode([string]$Root, [string]$Instance) {
  $file = "$Root\run\$Instance.service"
  if (Test-Path -LiteralPath $file) { return (Get-Content -LiteralPath $file -Raw).Trim() }
  return 'none'
}

function Get-LauncherArguments([string]$Root, [string]$Instance, [string]$Role, [bool]$Headless) {
  $a = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Root\bin\run.ps1`" -Root `"$Root`" -Instance $Instance -Role $Role"
  if ($Headless) { $a += ' -Headless' }
  return $a
}

function Register-FwdsTask([string]$Root, [string]$Instance, [string]$Role, [bool]$Headless, [bool]$NoService) {
  New-Item -ItemType Directory -Force -Path "$Root\run" | Out-Null
  Set-Content -LiteralPath "$Root\run\$Instance.headless" -Value ([int]$Headless) -Encoding ASCII
  if ($NoService) {
    Set-Content -LiteralPath "$Root\run\$Instance.service" -Value 'none' -Encoding ASCII
    Write-Step '按 -NoService 安装：没有注册开机自启（启动器的守护循环照常工作）'
    return
  }
  $user = "$env:USERDOMAIN\$env:USERNAME"
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (Get-LauncherArguments $Root $Instance $Role $Headless) -WorkingDirectory $Root
  # 当前用户登录时启动（界面要在用户的桌面上显示）。演示机设成开机自动登录，就等于开机自启
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
  # 任务失败时每 1 分钟重试（最多 999 次）；不限运行时长；已在运行就不再开第二份
  $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable `
              -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName (Get-TaskName $Instance) -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description "FWDS $Role ($Instance)，由 deploy\install.ps1 注册" -Force | Out-Null
  Set-Content -LiteralPath "$Root\run\$Instance.service" -Value 'task' -Encoding ASCII
  Write-Step "已注册计划任务 $(Get-TaskName $Instance)（登录时启动，启动器守护，失败每 1 分钟重试）"
}

function Start-Fwds([string]$Root, [string]$Instance, [string]$Role) {
  Remove-Item -LiteralPath "$Root\run\$Instance.stop" -ErrorAction SilentlyContinue
  if ((Get-ServiceMode $Root $Instance) -eq 'task') {
    Start-ScheduledTask -TaskName (Get-TaskName $Instance)
  } else {
    $headless = (Get-Content -LiteralPath "$Root\run\$Instance.headless" -ErrorAction SilentlyContinue) -eq '1'
    Start-Process -FilePath 'powershell.exe' -ArgumentList (Get-LauncherArguments $Root $Instance $Role $headless) `
      -WorkingDirectory $Root -WindowStyle Hidden | Out-Null
  }
}

# 停止：先放“停止标记”让启动器不再拉起，再结束程序进程，最后停掉任务
function Stop-Fwds([string]$Root, [string]$Instance) {
  New-Item -ItemType File -Force -Path "$Root\run\$Instance.stop" | Out-Null
  $pidFile = "$Root\run\$Instance.pid"
  if (Test-Path -LiteralPath $pidFile) {
    $procId = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($p -and $p.Path -like "$Root\app\*") { Stop-Process -Id $procId -Force; $p.WaitForExit(15000) | Out-Null }
    Remove-Item -LiteralPath $pidFile -ErrorAction SilentlyContinue
  }
  if ((Get-ServiceMode $Root $Instance) -eq 'task') {
    Stop-ScheduledTask -TaskName (Get-TaskName $Instance) -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 2
  Write-Step "已停止 $Instance"
}

function Test-FwdsRunning([string]$Root, [string]$Instance) {
  $pidFile = "$Root\run\$Instance.pid"
  if (-not (Test-Path -LiteralPath $pidFile)) { return $false }
  $p = Get-Process -Id ([int](Get-Content -LiteralPath $pidFile -Raw).Trim()) -ErrorAction SilentlyContinue
  return [bool]($p -and $p.Path -like "$Root\app\*")
}

# ---------- 冒烟检查（设计 8.4 节） ----------

function Wait-Log([string]$Log, [datetime]$Since, [string]$Pattern, [int]$Seconds) {
  for ($i = 0; $i -lt $Seconds; $i++) {
    # 启动器每次启动都换新的日志文件，所以只看修改时间在 Since 之后的那个
    if ((Test-Path -LiteralPath $Log) -and (Get-Item -LiteralPath $Log).LastWriteTime -ge $Since -and
        (Select-String -LiteralPath $Log -SimpleMatch -Pattern $Pattern -Quiet)) { return $true }
    Start-Sleep -Seconds 1
  }
  return $false
}

function Test-Smoke([string]$Root, [string]$Instance, [string]$Role, [datetime]$Since, [int]$ExpectLogin) {
  $log = "$Root\logs\$Instance.log"
  if (-not (Wait-Log $log $Since "fwds-$Role " 30)) { Write-Step '冒烟检查失败：30 秒内没有看到程序启动'; return $false }
  Start-Sleep -Seconds 5
  if (-not (Test-FwdsRunning $Root $Instance)) { Write-Step "冒烟检查失败：程序启动后退出了，见 $log"; return $false }
  if ($Role -eq 'server') {
    if (-not (Wait-Log $log $Since 'listening on' 15)) { Write-Step '冒烟检查失败：服务端没有开始监听'; return $false }
    Write-Step '冒烟检查：服务端已在监听'
  }
  if ($ExpectLogin -gt 0) {
    if (-not (Wait-Log $log $Since 'login ok' $ExpectLogin)) { Write-Step "冒烟检查失败：$ExpectLogin 秒内没有设备登录成功"; return $false }
    Write-Step '冒烟检查：设备登录成功'
  }
  return $true
}

# ---------- 备份、恢复与回滚（设计 8.4 节） ----------

function Get-Sha256([string]$File) { (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLower() }

# 备份项与 Linux / macOS 相同：配置、证书目录、固件签名公钥；服务端另有数据库和审计检查点
function New-Backup([string]$Root, [string]$Instance, [string]$Version, $CheckOutput) {
  $dir = "$Root\backup\$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))_$($Version)_$Instance"
  New-Item -ItemType Directory -Force -Path "$dir\pki" | Out-Null
  $cfg = "$Root\config\$Instance.ini"
  Copy-Item -LiteralPath $cfg -Destination "$dir\config.ini"
  Copy-Item -LiteralPath "$Root\pki\$Instance" -Destination "$dir\pki\$Instance" -Recurse
  Copy-Item -LiteralPath "$Root\pki\fsk.pub.pem" -Destination "$dir\pki\fsk.pub.pem"
  Write-Lines "$dir\check-before.txt" $CheckOutput
  $info = @("version=$Version", "instance=$Instance", "time=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
  $db = Get-IniValue $cfg 'server' 'db_file'
  if ($db) {
    Copy-Item -LiteralPath $db -Destination "$dir\fwds-server.db"
    $info += "db_sha256=$(Get-Sha256 $db)"
    $cp = Get-IniValue $cfg 'server' 'audit_checkpoint_file'
    if ($cp -and (Test-Path -LiteralPath $cp)) { Copy-Item -LiteralPath $cp -Destination "$dir\audit-checkpoint" }
  }
  Write-Lines "$dir\backup.txt" $info
  return $dir
}

function Get-KeyValue($Lines, [string]$Key) {
  foreach ($l in $Lines) { if ($l.StartsWith("$Key=")) { return $l.Substring($Key.Length + 1) } }
  return ''
}

function Restore-Backup([string]$Root, [string]$Instance, [string]$Backup) {
  $cfg = "$Root\config\$Instance.ini"
  Copy-Item -LiteralPath "$Backup\config.ini" -Destination $cfg -Force
  Remove-Item -LiteralPath "$Root\pki\$Instance" -Recurse -Force
  Copy-Item -LiteralPath "$Backup\pki\$Instance" -Destination "$Root\pki\$Instance" -Recurse
  Copy-Item -LiteralPath "$Backup\pki\fsk.pub.pem" -Destination "$Root\pki\fsk.pub.pem" -Force
  $db = Get-IniValue $cfg 'server' 'db_file'
  if ($db -and (Test-Path -LiteralPath "$Backup\fwds-server.db")) {
    # 恢复前的数据库改名留着，不删
    if (Test-Path -LiteralPath $db) { Move-Item -LiteralPath $db -Destination "$db.before-rollback-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))" }
    Copy-Item -LiteralPath "$Backup\fwds-server.db" -Destination $db
    $cp = Get-IniValue $cfg 'server' 'audit_checkpoint_file'
    if ($cp -and (Test-Path -LiteralPath "$Backup\audit-checkpoint")) { Copy-Item -LiteralPath "$Backup\audit-checkpoint" -Destination $cp -Force }
    $want = Get-KeyValue (Read-Lines "$Backup\backup.txt") 'db_sha256'
    $got = Get-Sha256 $db
    if ($want -ne $got) { Write-Step '恢复后的数据库和备份不一致'; return $false }
    Write-Step "数据库已从备份恢复，SHA-256 与备份时一致（$($got.Substring(0, 8))…）"
  }
  return $true
}

# 比较两份 --check 输出里的数据量和审计哈希链结论
function Test-SameData($Before, $After) {
  $same = $true
  foreach ($k in 'devices', 'firmware', 'releases', 'audit_rows', 'audit_chain') {
    $a = Get-KeyValue $Before $k; $b = Get-KeyValue $After $k
    if ($a -ne $b) { Write-Step "数据比对：$k 之前 $a，之后 $b"; $same = $false }
  }
  return $same
}

function Invoke-Rollback([string]$Root, [string]$Instance, [string]$Role, [string]$Backup, [int]$ExpectLogin) {
  $old = Get-KeyValue (Read-Lines "$Backup\backup.txt") 'version'
  if (-not (Test-Path -LiteralPath "$Root\app\$old")) { Write-Step "旧版本 $old 的程序已不在 $Root\app 里"; return $false }
  Write-Step "开始回滚到 $old（备份 $Backup）"
  Stop-Fwds $Root $Instance
  Write-Atomic (Get-CurrentFile $Root $Instance) $old
  if (-not (Restore-Backup $Root $Instance $Backup)) { return $false }
  $after = Invoke-Check $Root $old $Role $Instance ''
  if ($after.ExitCode -ne 0) { Write-Step "旧版本自检失败，见 $Root\logs\$Instance.check.log"; return $false }
  if ($Role -eq 'server') {
    if (-not (Test-SameData (Read-Lines "$Backup\check-before.txt") $after.Output)) { Write-Step '回滚后的数据与升级前不一致'; return $false }
    Write-Step '数据比对：设备、固件、发布、审计日志条数与升级前一致，审计哈希链完整'
  }
  $since = Get-Date
  Start-Fwds $Root $Instance $Role
  if (-not (Test-Smoke $Root $Instance $Role $since $ExpectLogin)) { return $false }
  Remove-Item -LiteralPath (Get-PreviousFile $Root $Instance) -ErrorAction SilentlyContinue
  Write-Step "回滚完成：当前版本 $old"
  return $true
}
