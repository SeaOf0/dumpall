#!/bin/sh

IR_MAX_OUTPUT_BYTES="${IR_MAX_OUTPUT_BYTES:-33554432}"

ir_init() {
    IR_NAME="$1"
    IR_OUT="$2"
    if [ -z "$IR_OUT" ]; then
        printf '%s\n' "缺少输出目录。" >&2
        exit 2
    fi
    mkdir -p "$IR_OUT"
    chmod 0700 "$IR_OUT" 2>/dev/null || true
    IR_STATUS="$IR_OUT/status.tsv"
    printf 'module\tstarted_at\tfinished_at\texit_code\toutput\n' > "$IR_STATUS"
}

ir_capture() {
    label="$1"
    seconds="$2"
    shift 2
    case "$label" in
        *[!A-Za-z0-9_.-]*|'') printf '非法输出标签: %s\n' "$label" >&2; return 2 ;;
    esac
    target="$IR_OUT/$label.txt"
    started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    blocks=$((IR_MAX_OUTPUT_BYTES / 512))
    set +e
    (
        ulimit -f "$blocks" 2>/dev/null || true
        if command -v timeout >/dev/null 2>&1; then
            timeout -k 5 "$seconds" "$@"
        else
            "$@"
        fi
    ) > "$target" 2>&1
    code=$?
    set -e
    finished="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$started" "$finished" "$code" "$target" >> "$IR_STATUS"
    return 0
}

ir_finish() {
    manifest="$IR_OUT/SHA256SUMS.txt"
    : > "$manifest"
    find "$IR_OUT" -type f ! -name SHA256SUMS.txt -exec sha256sum -- {} \; > "$manifest" 2>/dev/null || true
    chmod -R go-rwx "$IR_OUT" 2>/dev/null || true
    printf '完成: %s\n' "$IR_OUT"
}

ir_require_linux() {
    if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
        printf '%s\n' "该脚本只适用于 Linux。" >&2
        exit 1
    fi
}
