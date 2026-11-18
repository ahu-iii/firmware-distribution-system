#!/bin/bash
# deploy/package.sh：在签发主机上把 Release 版程序打成安装包（Linux / macOS）。Windows 用 deploy\package.ps1。
#   deploy/package.sh --build-dir build/release --fsk-dir local/fsk [--out dist] [--upx]
# 先构建：cmake --preset release -G Ninja -DFWDS_BUILD_TESTS=OFF && cmake --build --preset release
#
# 步骤（设计第 15 节）：
#   1. 拷贝 fwds-server、fwds-client，去掉符号表（strip）；
#   2. --upx：UPX 加壳（只在 Linux 上做；UPX 不支持当前版本的 macOS 程序）；
#   3. 用 FSK 给加壳后的程序签名（fwds-signer sign-exe，提示输入 FSK 口令），签名写到 <程序>.sig；
#      签名必须是最后一步：之后对程序的任何改动都会让启动自校验失败；
#   4. 拷贝部署脚本和配置模板，写 VERSION。
# 生成 <out>/fwds-<版本>-<系统>/，整个目录拷到目标机器上运行 deploy/install.sh。
# 包里没有任何私钥、口令和证书：这些在安装时由 --cert-dir 等参数另外提供。
set -u
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

BUILD="" FSK="" OUT=dist UPX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) BUILD=$2; shift 2 ;;
    --fsk-dir) FSK=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --upx) UPX=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "不认识的参数 $1" ;;
  esac
done
[ -n "$BUILD" ] && [ -n "$FSK" ] || die "缺少 --build-dir 或 --fsk-dir"
SRC=$(package_root)  # 在仓库里运行时就是仓库根目录
BIN="$BUILD/bin"
for p in fwds-server fwds-client fwds-signer; do [ -x "$BIN/$p" ] || die "没有 $BIN/$p，先构建 Release 版"; done
VERSION=$("$BIN/fwds-server" --version | awk '{print $2}')
[ -n "$VERSION" ] || die "读不出版本号"
OS=$(os_name)
DEST="$OUT/fwds-$VERSION-$OS"
[ -e "$DEST" ] && die "$DEST 已存在"
mkdir -p "$DEST/bin" "$DEST/deploy/lib" "$DEST/deploy/config"
say "打包 $VERSION（$OS）到 $DEST"

for p in fwds-server fwds-client; do
  cp "$BIN/$p" "$DEST/bin/"
  # 去掉符号表：函数名、源文件名不留在发出去的程序里（macOS 的 strip 去掉本地符号用 -x）
  if [ "$OS" = macos ]; then strip -x "$DEST/bin/$p"; else strip "$DEST/bin/$p"; fi
  if [ $UPX -eq 1 ]; then
    if [ "$OS" = macos ]; then
      say "macOS 不做 UPX 加壳（UPX 不支持当前的 macOS 程序格式），只做签名"
    else
      command -v upx >/dev/null || die "没有 upx（apt install upx-ucl）"
      upx -q --best "$DEST/bin/$p" >/dev/null || die "UPX 加壳 $p 失败"
      upx -q -t "$DEST/bin/$p" >/dev/null || die "UPX 自检 $p 失败"
      say "UPX 加壳：$p"
    fi
  fi
done

# 签名放在最后：签的是最终发出去的文件
"$BIN/fwds-signer" sign-exe --fsk-dir "$FSK" --exe "$DEST/bin/fwds-server" --exe "$DEST/bin/fwds-client" ||
  die "程序签名失败"

cp "$SRC/deploy/install.sh" "$SRC/deploy/upgrade.sh" "$SRC/deploy/rollback.sh" "$SRC/deploy/README.md" "$DEST/deploy/"
cp "$SRC/deploy/lib/common.sh" "$SRC/deploy/lib/run.sh" "$DEST/deploy/lib/"
cp "$SRC/deploy/config/test.ini" "$SRC/deploy/config/prod.ini" "$DEST/deploy/config/"
printf '%s\n' "$VERSION" >"$DEST/VERSION"
say "完成：$DEST"
ls -l "$DEST/bin"
