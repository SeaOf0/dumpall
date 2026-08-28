#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUTPUT=""; PARALLEL=0; DAYS=7
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --parallel) PARALLEL=1; shift ;;
        --days) DAYS="$2"; shift 2 ;;
        -h|--help) printf '用法: %s --output DIR [--parallel] [--days N]\n' "$0"; exit 0 ;;
        *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$OUTPUT" ] || { printf '%s\n' "缺少 --output" >&2; exit 2; }
mkdir -p "$OUTPUT"; chmod 0700 "$OUTPUT" 2>/dev/null || true
printf 'started_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$OUTPUT/run_info.txt"

"$SCRIPT_DIR/01_volatile_context.sh" --output "$OUTPUT/01_volatile"

can_parallel=0
if [ "$PARALLEL" -eq 1 ]; then
    mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || printf 0)"
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 1)"
    load="$(awk '{print int($1)}' /proc/loadavg 2>/dev/null || printf 999)"
    if [ "${mem_kb:-0}" -ge 4194304 ] && [ "${cpus:-1}" -ge 4 ] && [ "${load:-999}" -lt "${cpus:-1}" ]; then can_parallel=1; fi
fi

if [ "$can_parallel" -eq 1 ]; then
    "$SCRIPT_DIR/02_filesystem_metadata.sh" --output "$OUTPUT/02_filesystem" --days "$DAYS" & p1=$!
    "$SCRIPT_DIR/03_application_artifacts.sh" --output "$OUTPUT/03_applications" & p2=$!
    s1=0; s2=0
    wait "$p1" || s1=$?
    wait "$p2" || s2=$?
    printf 'parallel=2\nmodule_exit_codes=%s,%s\n' "$s1" "$s2" >> "$OUTPUT/run_info.txt"
else
    "$SCRIPT_DIR/02_filesystem_metadata.sh" --output "$OUTPUT/02_filesystem" --days "$DAYS"
    "$SCRIPT_DIR/03_application_artifacts.sh" --output "$OUTPUT/03_applications"
    printf 'parallel=0\n' >> "$OUTPUT/run_info.txt"
fi

printf 'finished_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTPUT/run_info.txt"
find "$OUTPUT" -type f ! -name SHA256SUMS.txt -exec sha256sum -- {} \; > "$OUTPUT/SHA256SUMS.txt" 2>/dev/null || true
chmod -R go-rwx "$OUTPUT" 2>/dev/null || true
printf '补充采集完成: %s\n' "$OUTPUT"
