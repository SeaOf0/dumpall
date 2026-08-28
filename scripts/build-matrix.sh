#!/usr/bin/env sh
# dumpall 多平台构建矩阵。
#
# Windows 与 Linux 产物相互独立：
#   Windows: amd64、x86（32 位）、ARM64
#   Linux: amd64、x86（32 位）、ARM64、ARM32
#
# 用法：
#   sh scripts/build-matrix.sh check   # 仅做交叉编译检查（无需交叉链接器）
#   sh scripts/build-matrix.sh build   # 构建当前平台 + 可链接的交叉目标
#
# `check` 验证全部目标，`build` 在链接器可用时生成独立平台产物。

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MODE="${1:-check}"
STRICT_BUILD="${STRICT_BUILD:-0}"
MINGW_X86_64_GCC="$(command -v x86_64-w64-mingw32-gcc 2>/dev/null || true)"

LLVM_MINGW_BIN="${LLVM_MINGW_ROOT:-$ROOT/.tools/llvm-mingw-current}/bin"
if [ -d "$LLVM_MINGW_BIN" ]; then
    PATH="$LLVM_MINGW_BIN:$PATH"
    export PATH
fi

LINUX_TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf i686-unknown-linux-musl"
WINDOWS_TARGETS="x86_64-pc-windows-gnu i686-pc-windows-gnu aarch64-pc-windows-gnullvm"

windows_artifact() {
    case "$1" in
        x86_64-pc-windows-gnu) echo "dumpall-windows-amd64.exe" ;;
        i686-pc-windows-gnu) echo "dumpall-windows-x86.exe" ;;
        aarch64-pc-windows-gnullvm) echo "dumpall-windows-arm64.exe" ;;
    esac
}

linux_artifact() {
    case "$1" in
        x86_64-unknown-linux-musl) echo "dumpall-linux-amd64-musl" ;;
        aarch64-unknown-linux-musl) echo "dumpall-linux-arm64-musl" ;;
        armv7-unknown-linux-musleabihf) echo "dumpall-linux-arm32" ;;
        i686-unknown-linux-musl) echo "dumpall-linux-x86-musl" ;;
    esac
}

fail=0
for target in $LINUX_TARGETS $WINDOWS_TARGETS; do
    if [ "$MODE" = "check" ]; then
        printf '==> check %s\n' "$target"
        cargo check --locked --features binary-evtx --target "$target" || fail=1
    else
        is_windows=0
        for w in $WINDOWS_TARGETS; do [ "$w" = "$target" ] && is_windows=1; done
        if [ "$is_windows" = "1" ]; then
            artifact="$(windows_artifact "$target")"
        else
            artifact="$(linux_artifact "$target")"
        fi
        printf '==> build %s -> dist/%s\n' "$target" "$artifact"
        mkdir -p dist
        if [ "$target" = "aarch64-pc-windows-gnullvm" ]; then
            export RUSTFLAGS="-C target-feature=+crt-static -C linker=aarch64-w64-mingw32-clang"
        elif [ "$target" = "x86_64-pc-windows-gnu" ]; then
            if [ -n "$MINGW_X86_64_GCC" ]; then
                export RUSTFLAGS="-C linker=$MINGW_X86_64_GCC"
            else
                export RUSTFLAGS="-C linker=x86_64-w64-mingw32-gcc"
            fi
        elif [ "$target" = "i686-pc-windows-gnu" ]; then
            export RUSTFLAGS="-C linker=$ROOT/scripts/link-i686-windows.sh"
        elif case "$target" in *musl*) true;; *) false;; esac; then
            export RUSTFLAGS="-C linker=rust-lld -C link-self-contained=yes"
        else
            export RUSTFLAGS=""
        fi
        if cargo build --release --locked --features binary-evtx --target "$target"; then
            bin="target/$target/release/dumpall"
            [ -f "$bin.exe" ] && bin="$bin.exe"
            cp "$bin" "dist/$artifact"
        else
            printf '    (skipped: cross linker for %s unavailable on this host)\n' "$target"
            [ "$STRICT_BUILD" = "1" ] && fail=1
        fi
    fi
done

if [ "$fail" != "0" ]; then
    exit 1
fi
