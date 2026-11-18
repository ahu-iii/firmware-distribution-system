# deploy\install.ps1：在干净的 Windows 10/11 上安装服务端或一台设备客户端（设计 8.3 节，检查项 3-2、8-1、8-2、8-3）。
# 在解压后的程序包里运行（包由 deploy\package.ps1 生成），用普通的 PowerShell 窗口即可：
#
#   服务端：
#   powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Role server -Root C:\fwds `
#       -CertDir <issue-cert 输出目录> -FskPub fsk.pub.pem -FskFingerprint <fsk-init 显示的指纹> -Listen 192.168.1.10
#   设备：
#   powershell -ExecutionPolicy Bypass -File deploy\install.ps1 -Role client -Root C:\fwds -DeviceId DEV-001 `
#       -CertDir <...> -FskPub fsk.pub.pem -FskFingerprint <...> -ServerHost 192.168.1.10 -License DEV-001.lic `
#       [-FactoryFw fw_v2.0.0.fwpkg]
#   其他选项：-Port（默认 9443）、-Model（默认 PLC-X200）、-ConfigTemplate、-Headless（不显示界面）、
#            -NoService（不注册计划任务，直接启动）
#
# 步骤与 deploy/install.sh 相同：依赖检查 → 建目录 → 装入程序 → 拷材料 → 生成配置 → 保存口令（DPAPI）
#       → 部署自检 → 出厂固件 → 注册计划任务 → 启动 → 冒烟检查。
param(
  [Parameter(Mandatory = $true)][ValidateSet('server', 'client')][string]$Role,
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$DeviceId,
  [Parameter(Mandatory = $true)][string]$CertDir,
  [Parameter(Mandatory = $true)][string]$FskPub,
  [Parameter(Mandatory = $true)][string]$FskFingerprint,
  [string]$Listen,
  [string]$ServerHost,
  [int]$Port = 9443,
  [string]$Model = 'PLC-X200',
  [string]$License,
  [string]$FactoryFw,
  [string]$ConfigTemplate,
  [switch]$Headless,
  [switch]$NoService
)
. "$PSScriptRoot\lib\common.ps1"

if ($Role -eq 'server') {
  $Instance = 'server'
  if (-not $Listen) { Stop-WithError '服务端需要 -Listen（监听地址）' }
} else {
  if (-not $DeviceId) { Stop-WithError '设备需要 -DeviceId' }
  if (-not $ServerHost -or -not $License) { Stop-WithError '设备需要 -ServerHost 和 -License' }
  $Instance = $DeviceId
}
$Package = Get-PackageRoot
$Version = Get-PackageVersion $Package
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$Root = (Resolve-Path $Root).Path
Start-Record $Root 'install' $Instance
Write-Step "安装 fwds-$Role $Version，实例 $Instance，安装目录 $Root"

# 1. 依赖检查：程序能运行（Qt、OpenSSL、VC++ 运行库都在）；材料文件都在
$exe = "$Package\bin\fwds-$Role.exe"
if (-not (Test-Path -LiteralPath $exe)) { Stop-WithError "包里没有 $exe" }
$probe = Invoke-Program $exe @('--version') $Package $null
if ($probe.ExitCode -ne 0 -and (Test-Path "$Package\bin\vc_redist.x64.exe")) {
  # 干净的机器上常缺 VC++ 运行库：windeployqt 把安装包放在了 bin 里，装上再试（会弹出管理员确认）
  Write-Step '程序运行不起来，先安装包里带的 VC++ 运行库'
  Start-Process -FilePath "$Package\bin\vc_redist.x64.exe" -ArgumentList '/install', '/quiet', '/norestart' -Verb RunAs -Wait
  $probe = Invoke-Program $exe @('--version') $Package $null
}
if ($probe.ExitCode -ne 0) { Stop-WithError "$exe 运行不起来（缺运行库？在资源管理器里双击它看报错）" }
Write-Step "依赖检查：$($probe.Output | Select-Object -First 1) 可以运行"
if (-not (Test-Path -LiteralPath "$exe.sig")) { Write-Step "警告：没有程序签名文件 $exe.sig（发布版会拒绝运行）" }
$type = if ($Role -eq 'server') { 'server' } else { 'device' }
$need = @("$CertDir\$type.pem", "$CertDir\$type.key", "$CertDir\ca.pem", "$CertDir\crl.pem", $FskPub)
if ($License) { $need += $License }
if ($FactoryFw) { $need += $FactoryFw }
foreach ($f in $need) { if (-not (Test-Path -LiteralPath $f)) { Stop-WithError "找不到 $f" } }
$CertDir = (Resolve-Path $CertDir).Path
$FskPub = (Resolve-Path $FskPub).Path
if ($License) { $License = (Resolve-Path $License).Path }
if ($FactoryFw) { $FactoryFw = (Resolve-Path $FactoryFw).Path }
if (-not $ConfigTemplate) { $ConfigTemplate = "$Package\deploy\config\prod.ini" }
if (Test-Path -LiteralPath "$Root\config\$Instance.ini") { Stop-WithError "$Root 里已经装过 $Instance；升级用 deploy\upgrade.ps1" }

# 2. 目录；安装目录只给当前用户（和 SYSTEM、管理员）访问
foreach ($d in 'app', 'bin', 'config', "pki\$Instance", "data\$Instance", 'logs', 'backup', 'run', 'state', 'secrets', 'audit') {
  New-Item -ItemType Directory -Force -Path "$Root\$d" | Out-Null
}
Protect-Directory $Root

# 3. 程序：整个包装进 app\<版本>\，再写本实例的 current
if (-not (Test-Path -LiteralPath "$Root\app\$Version")) {
  New-Item -ItemType Directory -Force -Path "$Root\app\$Version" | Out-Null
  Copy-Item -Path "$Package\bin", "$Package\deploy", "$Package\VERSION" -Destination "$Root\app\$Version" -Recurse
}
Copy-Item -LiteralPath "$Package\deploy\lib\run.ps1", "$Package\deploy\lib\common.ps1" -Destination "$Root\bin" -Force
Write-Atomic (Get-CurrentFile $Root $Instance) $Version
Write-Step "程序已装入 $Root\app\$Version"

# 4. 证书、私钥（AES-256-GCM 封装）、CA、CRL、固件签名公钥、许可证
$P = "$Root\pki\$Instance"
Copy-Item -LiteralPath "$CertDir\$type.pem", "$CertDir\$type.key", "$CertDir\ca.pem", "$CertDir\crl.pem" -Destination $P
Copy-Item -LiteralPath $FskPub -Destination "$Root\pki\fsk.pub.pem" -Force
if ($License) { Copy-Item -LiteralPath $License -Destination "$P\device.lic" }
Write-Step "证书和密钥材料已拷到 $P"

# 5. 配置：只留本角色的段，占位符全部填好；口令不写进配置
$cfg = "$Root\config\$Instance.ini"
Copy-Item -LiteralPath $ConfigTemplate -Destination $cfg
$D = "$Root\data\$Instance"
if ($Role -eq 'server') { Remove-IniSection $cfg 'client' } else { Remove-IniSection $cfg 'server'; Remove-IniSection $cfg 'rollout' }
Remove-IniSection $cfg 'signer'
Set-IniValue $cfg 'tls' 'ca_file' "$P\ca.pem"
Set-IniValue $cfg 'tls' 'crl_file' "$P\crl.pem"
if ($Role -eq 'server') {
  Set-IniValue $cfg 'server' 'listen_address' $Listen
  Set-IniValue $cfg 'server' 'listen_port' $Port
  Set-IniValue $cfg 'server' 'db_file' "$D\fwds-server.db"
  Set-IniValue $cfg 'server' 'firmware_dir' "$D\firmware"
  Set-IniValue $cfg 'server' 'audit_checkpoint_file' "$Root\audit\server.audit-checkpoint"
  Set-IniValue $cfg 'server' 'fsk_pub_file' "$Root\pki\fsk.pub.pem"
  Set-IniValue $cfg 'server' 'fsk_pub_sha256' $FskFingerprint
  Set-IniValue $cfg 'server' 'cert_file' "$P\server.pem"
  Set-IniValue $cfg 'server' 'key_file' "$P\server.key"
} else {
  Set-IniValue $cfg 'client' 'server_host' $ServerHost
  Set-IniValue $cfg 'client' 'server_port' $Port
  Set-IniValue $cfg 'client' 'device_id' $Instance
  Set-IniValue $cfg 'client' 'model' $Model
  Set-IniValue $cfg 'client' 'cert_file' "$P\device.pem"
  Set-IniValue $cfg 'client' 'key_file' "$P\device.key"
  Set-IniValue $cfg 'client' 'data_dir' $D
  Set-IniValue $cfg 'client' 'fsk_pub_file' "$Root\pki\fsk.pub.pem"
  Set-IniValue $cfg 'client' 'fsk_pub_sha256' $FskFingerprint
  Set-IniValue $cfg 'client' 'license_file' "$P\device.lic"
}
$left = Select-String -LiteralPath $cfg -Pattern '=<' -SimpleMatch
if ($left) { Stop-WithError "配置里还有没填的占位符：$($left | Select-Object -First 3 | ForEach-Object { $_.Line })" }
Write-Step "配置已生成：$cfg"

# 6. 私钥口令：DPAPI 加密保存
$secret = Save-Secret $Root $Instance
Write-Step "私钥口令已保存（$(Get-SecretFile $Root $Instance)，DPAPI 加密，只有当前 Windows 账户能解开）"

# 7. 部署自检；服务端同时建好数据库
$check = Invoke-Check $Root $Version $Role $Instance $secret
$secret = $null
if ($check.ExitCode -ne 0) {
  Write-Step "部署自检失败，原因见 $Root\logs\$Instance.check.log："
  Get-Content -LiteralPath "$Root\logs\$Instance.check.log" -Tail 5 | ForEach-Object { Write-Step "  $_" }
  Remove-Item -LiteralPath $cfg, (Get-SecretFile $Root $Instance) -ErrorAction SilentlyContinue
  Stop-WithError '安装中止（已删除生成的配置和口令，修正后重新运行）'
}
Write-Step "部署自检通过：$($check.Output -join ' ')"

# 8. 出厂固件（设备，可选）
if ($FactoryFw) {
  $r = Invoke-Program (Get-ExePath $Root $Version 'client') @('--config', $cfg, '--provision', $FactoryFw) $Root "$Root\logs\$Instance.check.log"
  if ($r.ExitCode -ne 0) { Stop-WithError "出厂写入失败，见 $Root\logs\$Instance.check.log" }
  Write-Step '出厂固件已写入分区 a'
}

# 9. 开机自启（登录时）和守护，然后启动
Register-FwdsTask $Root $Instance $Role $Headless.IsPresent $NoService.IsPresent
$since = Get-Date
Start-Fwds $Root $Instance $Role
if (-not (Test-Smoke $Root $Instance $Role $since 0)) { Stop-WithError '启动后冒烟检查失败' }
Write-Step "安装完成：$Instance 已启动，日志 $Root\logs\$Instance.log"
if ($Role -eq 'server') { Write-Step '下一步：在服务端界面创建维护员账号，注册设备' }
