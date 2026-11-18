#!/bin/bash
# deploy/install.sh：在干净的 Linux / macOS 机器上安装服务端或一台设备客户端（设计 8.3 节，检查项 3-2、8-1、8-2、8-3）。
# 在解压后的程序包里运行（包由 deploy/package.sh 生成，结构见 deploy/README.md）。
#
# 服务端：
#   deploy/install.sh --role server --root /opt/fwds --cert-dir <issue-cert 输出目录> \
#       --fsk-pub fsk.pub.pem --fsk-fingerprint <fsk-init 显示的指纹> --listen 192.168.1.10
# 设备：
#   deploy/install.sh --role client --root /opt/fwds --device-id DEV-001 --cert-dir <...> \
#       --fsk-pub fsk.pub.pem --fsk-fingerprint <...> --server-host 192.168.1.10 \
#       --license DEV-001.lic [--factory-fw fw_v2.0.0.fwpkg]
# 选项：
#   --port N              端口，默认 9443
#   --model M             设备型号，默认 PLC-X200
#   --config-template F   配置模板，默认包里的 deploy/config/prod.ini
#   --headless            不显示界面（Linux 默认就是 --headless，systemd 服务没有图形环境）
#   --no-service          不注册开机自启和守护，直接在后台启动（云端测试用）
#
# 步骤：依赖检查 → 建目录 → 装入程序 → 拷证书、公钥、许可证 → 从模板生成配置 → 保存私钥口令
#       → 部署自检（--check：配置、公钥指纹、程序签名、许可证、私钥口令；服务端顺带初始化数据库）
#       → 出厂固件（设备，可选）→ 注册开机自启和守护 → 启动 → 冒烟检查。
set -u
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# 新建的文件和目录只有运行账户能访问（证书目录、口令、数据库、日志都在安装目录下）
umask 077

ROLE="" ROOT="" INST="" CERT_DIR="" FSK_PUB="" FSK_FP="" LISTEN="" SERVER_HOST="" PORT=9443
MODEL=PLC-X200 LICENSE="" FACTORY_FW="" TEMPLATE="" HEADLESS=0 NO_SERVICE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE=$2; shift 2 ;;
    --root) ROOT=$2; shift 2 ;;
    --device-id) INST=$2; shift 2 ;;
    --cert-dir) CERT_DIR=$2; shift 2 ;;
    --fsk-pub) FSK_PUB=$2; shift 2 ;;
    --fsk-fingerprint) FSK_FP=$2; shift 2 ;;
    --listen) LISTEN=$2; shift 2 ;;
    --server-host) SERVER_HOST=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --model) MODEL=$2; shift 2 ;;
    --license) LICENSE=$2; shift 2 ;;
    --factory-fw) FACTORY_FW=$2; shift 2 ;;
    --config-template) TEMPLATE=$2; shift 2 ;;
    --headless) HEADLESS=1; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) die "不认识的参数 $1（--help 查看用法）" ;;
  esac
done

PKG=$(package_root)
OS=$(os_name)
[ "$OS" != other ] || die "只支持 Linux 和 macOS；Windows 用 deploy\\install.ps1"
case "$ROLE" in
  server) INST=server ;;
  client) [ -n "$INST" ] || die "设备需要 --device-id" ;;
  *) die "--role 必须是 server 或 client" ;;
esac
[ -n "$ROOT" ] || die "缺少 --root（安装目录）"
[ -n "$CERT_DIR" ] || die "缺少 --cert-dir（issue-cert 的输出目录）"
[ -n "$FSK_PUB" ] && [ -n "$FSK_FP" ] || die "缺少 --fsk-pub 或 --fsk-fingerprint"
[ "$ROLE" = server ] && { [ -n "$LISTEN" ] || die "服务端需要 --listen（监听地址）"; }
[ "$ROLE" = client ] && { [ -n "$SERVER_HOST" ] && [ -n "$LICENSE" ] || die "设备需要 --server-host 和 --license"; }
mkdir -p "$ROOT" || die "无法创建 $ROOT"
ROOT=$(cd "$ROOT" && pwd)
start_record "$ROOT" install "$INST"
VERSION=$(package_version "$PKG")
say "安装 fwds-$ROLE $VERSION，实例 $INST，安装目录 $ROOT（$OS）"

# 1. 依赖检查：程序能运行（Qt、OpenSSL 运行库都找得到）；材料文件都在
EXE="$PKG/bin/fwds-$ROLE"
[ -x "$EXE" ] || die "包里没有 $EXE"
"$EXE" --version >/dev/null 2>&1 || die "$EXE 运行不起来（缺 Qt 或 OpenSSL 运行库？先单独运行它看报错）"
say "依赖检查：$("$EXE" --version 2>/dev/null | head -1) 可以运行"
[ -f "$EXE.sig" ] || say "警告：没有程序签名文件 $EXE.sig（发布版会拒绝运行）"
TYPE=$([ "$ROLE" = server ] && echo server || echo device)
for f in "$CERT_DIR/$TYPE.pem" "$CERT_DIR/$TYPE.key" "$CERT_DIR/ca.pem" "$CERT_DIR/crl.pem" "$FSK_PUB" \
         ${LICENSE:+"$LICENSE"} ${FACTORY_FW:+"$FACTORY_FW"}; do
  [ -f "$f" ] || die "找不到 $f"
done
CERT_DIR=$(abs_path "$CERT_DIR")
FSK_PUB=$(abs_path "$FSK_PUB")
[ -n "$LICENSE" ] && LICENSE=$(abs_path "$LICENSE")
[ -n "$FACTORY_FW" ] && FACTORY_FW=$(abs_path "$FACTORY_FW")
TEMPLATE=${TEMPLATE:-"$PKG/deploy/config/prod.ini"}
[ -f "$TEMPLATE" ] || die "找不到配置模板 $TEMPLATE"
if [ $NO_SERVICE -eq 0 ]; then
  if [ "$OS" = linux ]; then
    command -v systemctl >/dev/null || die "没有 systemd；不注册服务请加 --no-service"
    [ "$(id -u)" -eq 0 ] || die "注册 systemd 服务需要 root：用 sudo 运行"
  else
    command -v launchctl >/dev/null || die "没有 launchctl"
    # launchd 用户代理装在当前用户名下，登录后由该用户的会话启动；用 sudo 会装到 root 名下
    [ "$(id -u)" -ne 0 ] || die "macOS 上不要用 sudo 运行（装到当前用户的 LaunchAgents 下）"
  fi
fi
[ -e "$ROOT/config/$INST.ini" ] && die "$ROOT 里已经装过 $INST；升级用 deploy/upgrade.sh"

# 2. 目录
chmod 700 "$ROOT"
mkdir -p "$ROOT"/{app,bin,config,pki/"$INST",data/"$INST",logs,backup,run}

# 3. 程序：整个包装进 app/<版本>/（同一台机器上的几个实例共用），再写本实例的 current
if [ ! -d "$ROOT/app/$VERSION" ]; then
  mkdir -p "$ROOT/app/$VERSION"
  cp -R "$PKG/bin" "$PKG/deploy" "$PKG/VERSION" "$ROOT/app/$VERSION/"
fi
cp "$PKG/deploy/lib/run.sh" "$PKG/deploy/lib/common.sh" "$ROOT/bin/"
chmod 700 "$ROOT/bin/run.sh"
mkdir -p "$ROOT/state"
write_atomic "$(current_file "$ROOT" "$INST")" "$VERSION"
say "程序已装入 $ROOT/app/$VERSION"

# 4. 证书、私钥（AES-256-GCM 封装）、CA、CRL、固件签名公钥、许可证
P="$ROOT/pki/$INST"
cp "$CERT_DIR/$TYPE.pem" "$CERT_DIR/$TYPE.key" "$CERT_DIR/ca.pem" "$CERT_DIR/crl.pem" "$P/"
cp "$FSK_PUB" "$ROOT/pki/fsk.pub.pem"
[ -n "$LICENSE" ] && cp "$LICENSE" "$P/device.lic"
say "证书和密钥材料已拷到 $P"

# 5. 配置：模板里的占位符全部按安装目录和参数填好；口令不写进配置
CFG="$ROOT/config/$INST.ini"
cp "$TEMPLATE" "$CFG"
D="$ROOT/data/$INST"
# 一份模板两端共用，生成时只留本角色的段（服务端去掉 [client]，设备去掉 [server]、[rollout]、[signer]）
if [ "$ROLE" = server ]; then
  ini_drop_section "$CFG" client
else
  ini_drop_section "$CFG" server
  ini_drop_section "$CFG" rollout
fi
ini_drop_section "$CFG" signer
ini_set "$CFG" tls ca_file "$P/ca.pem"
ini_set "$CFG" tls crl_file "$P/crl.pem"
if [ "$ROLE" = server ]; then
  ini_set "$CFG" server listen_address "$LISTEN"
  ini_set "$CFG" server listen_port "$PORT"
  ini_set "$CFG" server db_file "$D/fwds-server.db"
  ini_set "$CFG" server firmware_dir "$D/firmware"
  # 审计检查点放在数据目录之外，和数据库分开（设计第 13 章）
  mkdir -p "$ROOT/audit"
  ini_set "$CFG" server audit_checkpoint_file "$ROOT/audit/server.audit-checkpoint"
  ini_set "$CFG" server fsk_pub_file "$ROOT/pki/fsk.pub.pem"
  ini_set "$CFG" server fsk_pub_sha256 "$FSK_FP"
  ini_set "$CFG" server cert_file "$P/server.pem"
  ini_set "$CFG" server key_file "$P/server.key"
else
  ini_set "$CFG" client server_host "$SERVER_HOST"
  ini_set "$CFG" client server_port "$PORT"
  ini_set "$CFG" client device_id "$INST"
  ini_set "$CFG" client model "$MODEL"
  ini_set "$CFG" client cert_file "$P/device.pem"
  ini_set "$CFG" client key_file "$P/device.key"
  ini_set "$CFG" client data_dir "$D"
  ini_set "$CFG" client fsk_pub_file "$ROOT/pki/fsk.pub.pem"
  ini_set "$CFG" client fsk_pub_sha256 "$FSK_FP"
  ini_set "$CFG" client license_file "$P/device.lic"
fi
grep -q '=<' "$CFG" && die "配置里还有没填的占位符：$(grep '=<' "$CFG" | head -3 | tr '\n' ' ')"
say "配置已生成：$CFG"

# 6. 私钥口令
store_secret "$ROOT" "$INST"
say "私钥口令已保存（$([ "$OS" = macos ] && echo 登录钥匙串 || echo "$ROOT/secrets/$INST.pass，权限 600")）"

# 7. 部署自检：用安装好的程序、配置和口令走一遍启动检查；服务端同时建好数据库
if ! run_check "$ROOT" "$VERSION" "$ROLE" "$INST" >"$ROOT/run/$INST.check"; then
  say "部署自检失败，原因见 $ROOT/logs/$INST.check.log："
  tail -5 "$ROOT/logs/$INST.check.log"
  remove_secret "$ROOT" "$INST"
  rm -f "$CFG"
  die "安装中止（已删除生成的配置和口令，修正后重新运行）"
fi
say "部署自检通过：$(tr '\n' ' ' <"$ROOT/run/$INST.check")"
unset FWDS_KEY_PASSPHRASE

# 8. 出厂固件（设备，可选）：不需要私钥口令
if [ -n "$FACTORY_FW" ]; then
  ( cd "$ROOT" && "$(exe_path "$ROOT" "$VERSION" client)" --config "$CFG" --provision "$FACTORY_FW" ) \
    >>"$ROOT/logs/$INST.check.log" 2>&1 || die "出厂写入失败，见 $ROOT/logs/$INST.check.log"
  say "出厂固件已写入分区 a"
fi

# 9. 开机自启和守护，然后启动
EXTRA=""
if [ $HEADLESS -eq 1 ] || [ "$OS" = linux ]; then EXTRA="--headless"; fi
MODE=$([ $NO_SERVICE -eq 1 ] && echo none || { [ "$OS" = linux ] && echo systemd || echo launchd; })
register_service "$ROOT" "$INST" "$ROLE" "$MODE" "$EXTRA"
[ -n "${SUDO_USER:-}" ] && chown -R "$SUDO_USER" "$ROOT"
OFFSET=$(log_size "$ROOT/logs/$INST.log")
start_service "$ROOT" "$INST" "$ROLE"
smoke_after_start "$ROOT" "$INST" "$ROLE" "$OFFSET" 0 || die "启动后冒烟检查失败"
say "安装完成：$INST 已启动，日志 $ROOT/logs/$INST.log"
[ "$ROLE" = server ] && say "下一步：在服务端界面创建维护员账号，注册设备（设备证书在设备的 pki 目录里）"
exit 0
