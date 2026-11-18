#!/bin/bash
# 部署演练（云端 Linux 容器用）：打包 0.2.0 / 0.2.1 → 安装服务端和 DEV-001 → 升级 → 回滚
# → 坏包升级自动回滚 → ST-31 程序被改 → ST-32 许可证换机器、加壳前后字符串。
# 用法：tests/deploy_drill.sh <仓库目录> <空的工作目录>。先构建 build/release（0.2.0）和
# build/release-021（-DFWDS_VERSION=0.2.1），两者都打开 FWDS_REQUIRE_EXE_SIGNATURE。
# 需要 root（第 9 步临时改 machine-id 模拟另一台主机，结束时改回）、upx、sqlite3、openssl。
# 容器里没有服务端界面，第 2b 步直接写设备表代替“注册设备”，真机上不要这样做。
set -u
R=$1; S=$2
rm -rf "$S"; mkdir -p "$S"; cd "$S"
B=$R/build/release/bin
# 口令每次运行随机生成，不写在脚本里，也不出现在输出中
CA_PASS=$(openssl rand -hex 16); FSK_PASS=$(openssl rand -hex 16)
SRV_PASS=$(openssl rand -hex 16); DEV_PASS=$(openssl rand -hex 16)
step() { echo; echo "===== $* ====="; }
step "0. 签发材料（CA、服务端和 DEV-001 证书、FSK、许可证、出厂固件）"
export FWDS_CA_PASSPHRASE=$CA_PASS
$B/fwds-signer ca-init --ca-dir ca | head -2
FWDS_KEY_PASSPHRASE="$SRV_PASS" $B/fwds-signer issue-cert --ca-dir ca --type server --name 127.0.0.1 --out-dir pki/server | head -1
FWDS_KEY_PASSPHRASE="$DEV_PASS" $B/fwds-signer issue-cert --ca-dir ca --type device --name DEV-001 --out-dir pki/DEV-001 | head -1
export FWDS_FSK_PASSPHRASE=$FSK_PASS
$B/fwds-signer fsk-init --fsk-dir fsk | tee fsk.txt | grep 指纹
FP=$(grep 指纹 fsk.txt | sed 's/.*：//')
HW=$($B/fwds-client --hw-fingerprint)
echo "本机硬件指纹：${HW:0:8}…"
$B/fwds-signer issue-lic --fsk-dir fsk --device-id DEV-001 --hw-fingerprint "$HW" --days 30 --out DEV-001.lic
$B/fwds-signer make-image --model PLC-X200 --fw-version 2.0.0 --size 300000 --out fw200.bin
$B/fwds-signer sign-fw --fsk-dir fsk --image fw200.bin --model PLC-X200 --fw-version 2.0.0 --security-version 4 --out fw200.fwpkg | head -1

step "1. 打包 0.2.0 和 0.2.1（strip、UPX、sign-exe）"
"$R/deploy/package.sh" --build-dir "$R/build/release" --fsk-dir fsk --out dist --upx
"$R/deploy/package.sh" --build-dir "$R/build/release-021" --fsk-dir fsk --out dist --upx | tail -1
unset FWDS_FSK_PASSPHRASE FWDS_CA_PASSPHRASE

step "2. 安装服务端 0.2.0（--no-service：容器里没有 systemd）"
printf '%s\n%s\n' "$SRV_PASS" "$SRV_PASS" | dist/fwds-0.2.0-linux/deploy/install.sh --role server --root "$S/root" \
  --cert-dir pki/server --fsk-pub fsk/fsk.pub.pem --fsk-fingerprint "$FP" --listen 127.0.0.1 --port 19443 --no-service
echo "install exit=$?"

step "2b. 注册 DEV-001（真机在服务端界面“注册设备…”完成；容器里没有界面，直接写设备表后重启服务端）"
DFP=$(openssl x509 -in pki/DEV-001/device.pem -outform DER | sha256sum | cut -d' ' -f1)
NA=$(date -u -d "$(openssl x509 -in pki/DEV-001/device.pem -noout -enddate | cut -d= -f2)" +%Y-%m-%dT%H:%M:%SZ)
sqlite3 root/data/server/fwds-server.db "INSERT INTO device (device_id, model, group_tag, status, cert_fingerprint, cert_not_after) VALUES ('DEV-001','PLC-X200','canary','active','$DFP','$NA');"
bash -c ". root/bin/common.sh; stop_service $S/root server; start_service $S/root server server"
sleep 3

step "3. 安装设备 DEV-001 0.2.0（含出厂固件）"
printf '%s\n%s\n' "$DEV_PASS" "$DEV_PASS" | dist/fwds-0.2.0-linux/deploy/install.sh --role client --root "$S/root" \
  --device-id DEV-001 --cert-dir pki/DEV-001 --fsk-pub fsk/fsk.pub.pem --fsk-fingerprint "$FP" \
  --server-host 127.0.0.1 --port 19443 --license DEV-001.lic --factory-fw fw200.fwpkg --no-service
echo "install exit=$?"
sleep 3
grep -h "login ok" root/logs/server.log root/logs/DEV-001.log | tail -2

step "4. FT-20 升级服务端 0.2.0 → 0.2.1（要求设备重新登录成功）"
dist/fwds-0.2.1-linux/deploy/upgrade.sh --root "$S/root" --instance server --expect-login 60
echo "upgrade exit=$?  server=$(cat root/state/server.current) DEV-001=$(cat root/state/DEV-001.current)"

step "5. 升级设备 DEV-001 0.2.0 → 0.2.1"
dist/fwds-0.2.1-linux/deploy/upgrade.sh --root "$S/root" --instance DEV-001
echo "upgrade exit=$?  server=$(cat root/state/server.current) DEV-001=$(cat root/state/DEV-001.current)"

step "6. FT-21 回滚服务端 0.2.1 → 0.2.0"
root/app/0.2.1/deploy/rollback.sh --root "$S/root" --instance server --expect-login 60
echo "rollback exit=$?  server=$(cat root/state/server.current) DEV-001=$(cat root/state/DEV-001.current)"

step "7. 升级失败自动回滚：0.2.2 包里的 fwds-server 被改了 1 字节（签名不符，新版本自检失败）"
cp -R dist/fwds-0.2.1-linux dist/fwds-0.2.2-broken
echo 0.2.2 > dist/fwds-0.2.2-broken/VERSION
python3 -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[len(b)//2]^=1; open(p,'wb').write(b)" dist/fwds-0.2.2-broken/bin/fwds-server
dist/fwds-0.2.2-broken/deploy/upgrade.sh --root "$S/root" --instance server --expect-login 60
echo "upgrade exit=$?  server=$(cat root/state/server.current)"
tail -2 root/logs/server.check.log

step "8. ST-31 改已安装的 fwds-client 1 字节后启动"
cp root/app/0.2.1/bin/fwds-client tampered-client; cp root/app/0.2.1/bin/fwds-client.sig tampered-client.sig
python3 -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[len(b)//2]^=1; open(p,'wb').write(b)" tampered-client
FWDS_KEY_PASSPHRASE="$DEV_PASS" ./tampered-client --config root/config/DEV-001.ini --check; echo "exit=$?（7 = 程序自校验失败）"
rm -f tampered-client.sig
FWDS_KEY_PASSPHRASE="$DEV_PASS" ./tampered-client --config root/config/DEV-001.ini --check; echo "exit=$?（发布版缺签名文件同样拒绝运行）"

step "9. ST-32 许可证拷到另一台机器（把本机的 machine-id 换掉模拟另一台主机）"
cp /etc/machine-id machine-id.bak; cp /var/lib/dbus/machine-id dbus-machine-id.bak
echo 0123456789abcdef0123456789abcdef > /etc/machine-id; cp /etc/machine-id /var/lib/dbus/machine-id
echo "另一台主机的硬件指纹：$(root/app/0.2.1/bin/fwds-client --hw-fingerprint | cut -c1-8)…"
FWDS_KEY_PASSPHRASE="$DEV_PASS" root/app/0.2.1/bin/fwds-client --config root/config/DEV-001.ini --check; echo "exit=$?（8 = 许可证检查失败）"
cp machine-id.bak /etc/machine-id; cp dbus-machine-id.bak /var/lib/dbus/machine-id
FWDS_KEY_PASSPHRASE="$DEV_PASS" root/app/0.2.1/bin/fwds-client --config root/config/DEV-001.ini --check >/dev/null 2>&1; echo "换回本机后 exit=$?"

step "10. ST-32 加壳前后的明文字符串"
for f in "$R/build/release/bin/fwds-client" root/app/0.2.1/bin/fwds-client; do
  echo "$f"
  echo "  文件大小 $(wc -c <"$f") 字节；可读字符串 $(strings -n 6 "$f" | wc -l) 条"
  for pat in "FWDS-LIC-1" "FWDS-EXE-1" "license_file" "login ok" "fsk_pub_sha256"; do
    echo "  \"$pat\"：单字节编码 $(strings -a "$f" | grep -c -- "$pat") 处，UTF-16 $(strings -a -e l "$f" | grep -c -- "$pat") 处"
  done
done

step "11. 收尾"
bash -c ". root/bin/common.sh; stop_service $S/root DEV-001; stop_service $S/root server"
ls -l root root/backup root/logs
