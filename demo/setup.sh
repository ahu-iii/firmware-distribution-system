#!/usr/bin/env bash
# 一键准备答辩演示环境（macOS / Linux）。在仓库根目录或任何位置运行都可以：
#   demo/setup.sh
# 做的事情（全部生成在 local/demo/ 下，不进仓库）：
#   1. 自建 CA，签发服务端证书和 DEV-001 ~ DEV-004 四台设备的证书
#   2. 生成固件签名密钥 FSK，签发四台设备的许可证（绑定本机硬件指纹，所以必须在演示机上运行）
#   3. 生成四个演示固件包：2.0.0（出厂）、2.1.0（正常升级）、2.2.0（自检失败，演示回滚）、1.9.0（降级，演示被拒）
#   4. 生成服务端和每台设备的配置，给四台设备出厂写入 2.0.0
#   5. 用 fwds-demo-seed 建三个账号、注册四台设备、导入固件（和界面操作走同一套接口，记审计日志）
#   6. 把准备好的数据存一份快照，demo/reset.sh 用它在几秒内回到演示前的状态
# 只问两个口令：演示密钥口令（CA、FSK、全部私钥共用）和演示账号口令（三个账号共用）。
# 口令只在本次运行的内存里，不写进任何文件；start.sh 启动时再输一次密钥口令。
source "$(dirname "$0")/lib.sh"

need_bins
if [ -e "$D" ]; then
  stop_all 2>/dev/null || true
  read -r -p "$D 已存在，重新生成会删除其中的证书、密钥和数据。继续？(y/N) " ans
  [ "$ans" = y ] || [ "$ans" = Y ] || exit 0
  rm -rf "$D"
fi
mkdir -p "$D"/{conf,img,fw,lic,run,logs}

echo "演示密钥口令：CA、固件签名密钥和全部私钥共用，至少 12 个字符。"
read_secret KEYPASS "演示密钥口令：" 12 twice
echo "演示账号口令：维护员、操作员、审计员共用，至少 10 个字符，含字母和数字。"
read_secret ACCPASS "演示账号口令：" 10 twice

signer() { "$BIN/fwds-signer" "$@"; }
# 签发工具从环境变量取口令（取后清除）。只给这一条命令设置，不 export 到整个脚本
with_ca() { FWDS_CA_PASSPHRASE=$KEYPASS FWDS_KEY_PASSPHRASE=$KEYPASS "$@"; }
with_fsk() { FWDS_FSK_PASSPHRASE=$KEYPASS "$@"; }

# 把 ini 文件中 [section] 里的 key 改成 value（key 在不同段里可能重名，所以按段改）
ini_set() {
  local file=$1 section=$2 key=$3 value=$4 tmp
  tmp=$(mktemp)
  awk -v s="[$section]" -v k="$key" -v v="$value" '
    /^\[/ { cur = $0 }
    cur == s && index($0, k "=") == 1 { print k "=" v; next }
    { print }' "$file" >"$tmp"
  mv "$tmp" "$file"
}

say "1/6 固件签名密钥 FSK"
FSK_OUT=$(with_fsk signer fsk-init --fsk-dir "$D/fsk")
FSK_SHA=$(printf '%s\n' "$FSK_OUT" | grep -Eo '[0-9a-f]{64}' | head -n 1)
[ -n "$FSK_SHA" ] || die "没有从 fsk-init 的输出里取到公钥指纹"
echo "  公钥指纹 $FSK_SHA"

say "2/6 配置文件（由 deploy/config/dev.ini 生成）"
SERVER_INI=$D/conf/server.ini
cp deploy/config/dev.ini "$SERVER_INI"
ini_set "$SERVER_INI" server listen_port "$PORT"
ini_set "$SERVER_INI" server db_file "$D/data/fwds-server.db"
ini_set "$SERVER_INI" server firmware_dir "$D/data/firmware"
ini_set "$SERVER_INI" server audit_checkpoint_file "$D/data/fwds-server.audit-checkpoint"
ini_set "$SERVER_INI" server log_dir "$D/logs"
ini_set "$SERVER_INI" server fsk_pub_file "$D/fsk/fsk.pub.pem"
ini_set "$SERVER_INI" server fsk_pub_sha256 "$FSK_SHA"
ini_set "$SERVER_INI" server cert_file "$D/pki/server/server.pem"
ini_set "$SERVER_INI" server key_file "$D/pki/server/server.key"
ini_set "$SERVER_INI" tls ca_file "$D/ca/ca.pem"
ini_set "$SERVER_INI" tls crl_file "$D/ca/crl.pem"
ini_set "$SERVER_INI" rollout observe_s 15   # 观察期缩短到 15 秒，现场不用干等
ini_set "$SERVER_INI" log level INFO
for dev in "${DEVICES[@]}"; do
  ini="$D/conf/$dev.ini"
  cp "$SERVER_INI" "$ini"
  ini_set "$ini" client server_port "$(port_of "$dev")"
  ini_set "$ini" client device_id "$dev"
  ini_set "$ini" client model "$MODEL"
  ini_set "$ini" client cert_file "$D/pki/$dev/device.pem"
  ini_set "$ini" client key_file "$D/pki/$dev/device.key"
  ini_set "$ini" client data_dir "$D/device/$dev"
  ini_set "$ini" client fsk_pub_file "$D/fsk/fsk.pub.pem"
  ini_set "$ini" client fsk_pub_sha256 "$FSK_SHA"
  ini_set "$ini" client license_file "$D/lic/$dev.lic"
  ini_set "$ini" client reboot_delay_ms 8000   # “重启中”停 8 秒，留出讲解和点“模拟断网”的时间
done

say "3/6 自建 CA，签发服务端和设备证书"
with_ca signer ca-init --ca-dir "$D/ca" --config "$SERVER_INI" >/dev/null
with_ca signer issue-cert --ca-dir "$D/ca" --type server --name 127.0.0.1 \
  --out-dir "$D/pki/server" --config "$SERVER_INI" >/dev/null
for dev in "${DEVICES[@]}"; do
  with_ca signer issue-cert --ca-dir "$D/ca" --type device --name "$dev" \
    --out-dir "$D/pki/$dev" --config "$SERVER_INI" >/dev/null
  echo "  $dev"
done

say "4/6 设备许可证（绑定本机硬件指纹）"
HW=$("$BIN/fwds-client" --hw-fingerprint)
for dev in "${DEVICES[@]}"; do
  with_fsk signer issue-lic --fsk-dir "$D/fsk" --device-id "$dev" --hw-fingerprint "$HW" \
    --out "$D/lic/$dev.lic" >/dev/null
done

say "5/6 演示固件包"
# 版本、安全版本号、大小、说明、是否自检失败。2.1.0 做得大一些，经慢速链路下载约 16 秒，来得及点紧急停止
make_pkg() {
  local ver=$1 sv=$2 size=$3 note=$4 fail=${5:-}
  signer make-image --model "$MODEL" --fw-version "$ver" --size "$size" ${fail:+--selftest-fail} \
    --out "$D/img/fw_$ver.bin" >/dev/null
  with_fsk signer sign-fw --fsk-dir "$D/fsk" --image "$D/img/fw_$ver.bin" --model "$MODEL" \
    --fw-version "$ver" --security-version "$sv" --note "$note" --out "$D/fw/fw_${ver}_sv$sv.fwpkg" >/dev/null
  echo "  fw_${ver}_sv$sv.fwpkg  $note"
}
make_pkg 2.0.0 4 8388608 "出厂固件"
make_pkg 2.1.0 5 33554432 "正常升级"
make_pkg 2.2.0 6 8388608 "自检失败（演示回滚）" fail
make_pkg 1.9.0 3 8388608 "旧版本（演示防降级）"
rm -rf "$D/img"

say "6/6 设备出厂写入 2.0.0，服务端建账号、注册设备、导入固件"
for dev in "${DEVICES[@]}"; do
  "$BIN/fwds-client" --config "$D/conf/$dev.ini" --provision "$D/fw/fw_2.0.0_sv4.fwpkg" \
    >"$D/logs/provision-$dev.log" 2>&1 || die "$dev 出厂写入失败，见 $D/logs/provision-$dev.log"
done
seed_args=(--config "$SERVER_INI" --maintainer maint01 --operator oper01 --auditor audit01)
for dev in "${DEVICES[@]}"; do
  seed_args+=(--device "$D/pki/$dev/device.pem,$MODEL,$(group_of "$dev")")
done
for pkg in "$D"/fw/fw_2.1.0_sv5.fwpkg "$D"/fw/fw_2.2.0_sv6.fwpkg "$D"/fw/fw_1.9.0_sv3.fwpkg; do
  seed_args+=(--firmware "$pkg")
done
FWDS_DEMO_ACCOUNT_PASSWORD=$ACCPASS "$BIN/fwds-demo-seed" "${seed_args[@]}" | sed 's/^/  /'
unset KEYPASS ACCPASS

# 快照：reset.sh 从这里恢复服务端数据库、固件库和四台设备的分区
rm -rf "$D/snapshot"
mkdir -p "$D/snapshot"
cp -R "$D/data" "$D/device" "$D/snapshot/"

say "准备完成"
cat <<EOF
  账号：维护员 maint01、操作员 oper01、审计员 audit01（口令是刚才设置的演示账号口令）
  设备：DEV-001、DEV-003、DEV-004 分组 line-A，DEV-002 分组 canary（经慢速链路），型号 $MODEL，均运行 2.0.0
  固件库：2.1.0（安全版本号 5）、2.2.0（6，自检失败）、1.9.0（3，降级）
下一步：demo/start.sh 启动（输入演示密钥口令）；演示完或出错时 demo/reset.sh 回到这个状态。
EOF
