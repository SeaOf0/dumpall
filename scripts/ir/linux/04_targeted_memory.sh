#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ir_require_linux

OUTPUT=""; PIDS=""; GCORE=""; CAPTURE=0; MIN_FREE_GB=4
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --pid) case "$2" in *[!0-9]*|'') exit 2 ;; esac; PIDS="$PIDS $2"; shift 2 ;;
        --gcore) GCORE="$2"; shift 2 ;;
        --capture-dump) CAPTURE=1; shift ;;
        --min-free-gb) MIN_FREE_GB="$2"; shift 2 ;;
        -h|--help) printf '用法: %s --output DIR --pid PID [--pid PID] [--capture-dump --gcore PATH] [--min-free-gb N]\n' "$0"; exit 0 ;;
        *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$PIDS" ] || { printf '%s\n' "至少指定一个 --pid" >&2; exit 2; }
ir_init targeted_memory "$OUTPUT"

for pid in $PIDS; do
    [ -d "/proc/$pid" ] || { printf '%s\t%s\tmissing\n' "$pid" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$IR_STATUS"; continue; }
    pid_dir="$IR_OUT/pid_$pid"; mkdir -p "$pid_dir"; chmod 0700 "$pid_dir"
    for item in status maps smaps_rollup cgroup limits mountinfo; do
        [ -r "/proc/$pid/$item" ] && sed -n '1,20000p' "/proc/$pid/$item" > "$pid_dir/$item.txt" 2>&1 || true
    done
    readlink "/proc/$pid/exe" > "$pid_dir/exe.txt" 2>&1 || true
    tr '\000' ' ' < "/proc/$pid/cmdline" > "$pid_dir/cmdline.txt" 2>/dev/null || true
    find "/proc/$pid/fd" -maxdepth 1 -type l -exec ls -l {} \; > "$pid_dir/fds.txt" 2>&1 || true
    if [ "$CAPTURE" -eq 1 ]; then
        [ -n "$GCORE" ] && [ -x "$GCORE" ] || { printf '%s\n' "--capture-dump 需要可信的 --gcore 可执行文件" >&2; exit 2; }
        free_kb="$(df -Pk "$IR_OUT" | awk 'NR==2 {print $4}')"
        required_kb=$((MIN_FREE_GB * 1024 * 1024))
        [ "${free_kb:-0}" -ge "$required_kb" ] || { printf 'PID %s: 磁盘空间不足，跳过 dump\n' "$pid" >> "$pid_dir/dump_status.txt"; continue; }
        if command -v timeout >/dev/null 2>&1; then
            timeout -k 10 300 "$GCORE" -o "$pid_dir/process" "$pid" > "$pid_dir/gcore.log" 2>&1 || true
        else
            "$GCORE" -o "$pid_dir/process" "$pid" > "$pid_dir/gcore.log" 2>&1 || true
        fi
    fi
done
ir_finish
