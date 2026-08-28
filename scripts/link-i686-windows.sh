#!/usr/bin/env bash
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# llvm-mingw 工具链根目录可用环境变量 LLVM_MINGW_ROOT 覆盖
LLVM_ROOT="${LLVM_MINGW_ROOT:-$ROOT/.tools/llvm-mingw-current}"
GCC_LIB=""
GCC_LIB_ARCHIVE=""
if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    candidate="$(i686-w64-mingw32-gcc -print-file-name=libgcc_eh.a)"
    if [ -f "$candidate" ]; then
        GCC_LIB="$candidate"
        GCC_LIB_DIR="$(CDPATH= cd -- "$(dirname -- "$GCC_LIB")" && pwd)"
        GCC_LIB_ARCHIVE="$GCC_LIB_DIR/libgcc.a"
    fi
fi
STUB_DIR="${TMPDIR:-/tmp}/dumpall-i686-unwind"
mkdir -p "$STUB_DIR"
STUB_OBJECT="$STUB_DIR/unwind-stubs.o"
if [ ! -f "$STUB_OBJECT" ]; then
    "$LLVM_ROOT/bin/clang" -target i686-w64-windows-gnu -c \
        "$ROOT/scripts/i686-unwind-stubs.c" -o "$STUB_OBJECT"
fi
args=()
for arg in "$@"; do
    case "$arg" in
        -lgcc_eh)
            args+=("$LLVM_ROOT/i686-w64-mingw32/lib/libunwind.a")
            [ -z "$GCC_LIB" ] || args+=("$GCC_LIB") ;;
        -lgcc)
            args+=("$LLVM_ROOT/lib/clang/22/lib/windows/libclang_rt.builtins-i386.a")
            [ -z "$GCC_LIB_ARCHIVE" ] || args+=("$GCC_LIB_ARCHIVE") ;;
        -l:libpthread.a)
            ;;
        *) args+=("$arg") ;;
    esac
done

exec "$LLVM_ROOT/bin/i686-w64-mingw32-clang" \
    -Wl,--allow-multiple-definition \
    "$STUB_OBJECT" \
    "${args[@]}"
