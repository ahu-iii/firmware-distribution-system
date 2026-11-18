# deploy\package.ps1：在签发主机（Windows）上把 Release 版程序打成安装包（设计第 15 节，ST-31、ST-32）。
# 先在 “Developer PowerShell for VS 2022” 里构建 Release 版：
#   cmake --preset release -G Ninja -DCMAKE_PREFIX_PATH="$Qt" -DOPENSSL_ROOT_DIR="$Ssl" -DFWDS_BUILD_TESTS=OFF
#   cmake --build --preset release
# 再打包：
#   powershell -ExecutionPolicy Bypass -File deploy\package.ps1 -BuildDir build\release -QtDir $Qt -OpenSslDir $Ssl `
#       -FskDir local\fsk [-Upx C:\tools\upx\upx.exe] [-Out dist]
# 步骤：
#   1. 拷贝 fwds-server.exe、fwds-client.exe；
#   2. windeployqt：把 Qt 的 DLL、平台插件、SQLite 驱动、TLS 后端插件和 VC++ 运行库安装包放进 bin\；
#      再拷 OpenSSL 的两个 DLL（windeployqt 不带）；
#   3. UPX 加壳（只压缩我们自己的两个 exe，Qt 和 OpenSSL 的 DLL 不动）；不给 -Upx 就跳过并提示；
#   4. 用 FSK 给加壳后的 exe 签名（fwds-signer sign-exe，提示输入 FSK 口令），签名写到 <exe>.sig。
#      签名必须是最后一步：之后再改 exe（包括重新加壳）启动自校验就会失败；
#   5. 拷贝部署脚本和配置模板，写 VERSION。
# 生成 <Out>\fwds-<版本>-windows\。包里没有任何私钥、口令和证书。
param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [Parameter(Mandatory = $true)][string]$QtDir,
  [Parameter(Mandatory = $true)][string]$OpenSslDir,
  [Parameter(Mandatory = $true)][string]$FskDir,
  [string]$Upx,
  [string]$Out = 'dist'
)
. "$PSScriptRoot\lib\common.ps1"
$Src = Get-PackageRoot   # 在仓库里运行时就是仓库根目录

$bin = Join-Path $BuildDir 'bin'
foreach ($p in 'fwds-server.exe', 'fwds-client.exe', 'fwds-signer.exe') {
  if (-not (Test-Path -LiteralPath "$bin\$p")) { Stop-WithError "没有 $bin\$p，先构建 Release 版" }
}
$env:PATH = "$QtDir\bin;$OpenSslDir\bin;$env:PATH"
$probe = Invoke-Program "$bin\fwds-server.exe" @('--version') $Src $null
$Version = (($probe.Output | Select-Object -First 1) -split ' ')[1]
if (-not $Version) { Stop-WithError '读不出版本号' }
$Dest = Join-Path $Out "fwds-$Version-windows"
if (Test-Path -LiteralPath $Dest) { Stop-WithError "$Dest 已存在" }
New-Item -ItemType Directory -Force -Path "$Dest\bin", "$Dest\deploy\lib", "$Dest\deploy\config" | Out-Null
Write-Step "打包 $Version（windows）到 $Dest"

# 1、2. 程序和运行库
Copy-Item -LiteralPath "$bin\fwds-server.exe", "$bin\fwds-client.exe" -Destination "$Dest\bin"
$wdq = Invoke-Program "$QtDir\bin\windeployqt.exe" @('--release', '--compiler-runtime', '--no-translations',
        "$Dest\bin\fwds-server.exe", "$Dest\bin\fwds-client.exe") $Src $null
if ($wdq.ExitCode -ne 0) { Stop-WithError 'windeployqt 失败' }
$ssl = Get-ChildItem -LiteralPath "$OpenSslDir\bin" -Filter 'lib*-3-x64.dll' | Where-Object { $_.Name -match '^lib(ssl|crypto)-3-x64\.dll$' }
if (@($ssl).Count -ne 2) { Stop-WithError "$OpenSslDir\bin 里没有 libssl-3-x64.dll 和 libcrypto-3-x64.dll" }
$ssl | Copy-Item -Destination "$Dest\bin"
Write-Step 'windeployqt 完成，OpenSSL 运行库已拷入'

# 3. UPX 加壳
if ($Upx) {
  foreach ($p in 'fwds-server.exe', 'fwds-client.exe') {
    $r = Invoke-Program $Upx @('-q', '--best', "$Dest\bin\$p") $Src $null
    if ($r.ExitCode -ne 0) { Stop-WithError "UPX 加壳 $p 失败" }
    $t = Invoke-Program $Upx @('-q', '-t', "$Dest\bin\$p") $Src $null
    if ($t.ExitCode -ne 0) { Stop-WithError "UPX 自检 $p 失败" }
    Write-Step "UPX 加壳：$p"
  }
} else {
  Write-Step '警告：没有给 -Upx，跳过加壳（ST-32 要求发布版加壳）'
}

# 4. 签名（提示输入 FSK 口令）
& "$bin\fwds-signer.exe" sign-exe --fsk-dir $FskDir --exe "$Dest\bin\fwds-server.exe" --exe "$Dest\bin\fwds-client.exe"
if ($LASTEXITCODE -ne 0) { Stop-WithError '程序签名失败' }

# 5. 部署脚本、配置模板、版本号
Copy-Item -LiteralPath "$Src\deploy\install.ps1", "$Src\deploy\upgrade.ps1", "$Src\deploy\rollback.ps1", "$Src\deploy\README.md" -Destination "$Dest\deploy"
Copy-Item -LiteralPath "$Src\deploy\lib\common.ps1", "$Src\deploy\lib\run.ps1" -Destination "$Dest\deploy\lib"
Copy-Item -LiteralPath "$Src\deploy\config\test.ini", "$Src\deploy\config\prod.ini" -Destination "$Dest\deploy\config"
Set-Content -LiteralPath "$Dest\VERSION" -Value $Version -Encoding ASCII
Write-Step "完成：$Dest"
Get-ChildItem -LiteralPath "$Dest\bin" -Filter 'fwds-*' | Format-Table Name, Length -AutoSize
