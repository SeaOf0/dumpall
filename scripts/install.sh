#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ]; then
    printf "%s\n" "install.sh 仅安装 Linux 二进制；Windows 请运行 install.ps1。" >&2
    exit 1
fi

case "$ARCH" in
    x86_64|amd64) BIN="dumpall-linux-amd64-musl" ;;
    i386|i686|x86) BIN="dumpall-linux-x86-musl" ;;
    aarch64|arm64) BIN="dumpall-linux-arm64-musl" ;;
    armv7l|armv7) BIN="dumpall-linux-arm32" ;;
    *) printf "不支持的 Linux 架构: %s\n" "$ARCH" >&2; exit 1 ;;
esac

SOURCE="$ROOT/bin/$BIN"
if [ ! -f "$SOURCE" ]; then
    printf "缺少匹配的发布文件: %s\n" "$SOURCE" >&2
    exit 1
fi

if [ -w /usr/local/bin ]; then
    DEST_DIR=/usr/local/bin
else
    DEST_DIR="${HOME:-.}/.local/bin"
    mkdir -p "$DEST_DIR"
fi

if [ -e "$DEST_DIR/dumpall" ]; then
    printf "目标已存在，未覆盖: %s\n" "$DEST_DIR/dumpall" >&2
    exit 1
fi
cp "$SOURCE" "$DEST_DIR/dumpall"
chmod 0755 "$DEST_DIR/dumpall"
printf "已安装: %s\n" "$DEST_DIR/dumpall"
