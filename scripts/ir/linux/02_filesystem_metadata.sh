#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ir_require_linux

OUTPUT=""; DAYS=7
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        -h|--help) printf '用法: %s --output DIR [--days N]\n' "$0"; exit 0 ;;
        *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
    esac
done
case "$DAYS" in *[!0-9]*|'') printf '%s\n' "--days 必须是正整数" >&2; exit 2 ;; esac
[ "$DAYS" -gt 0 ] || exit 2
ir_init filesystem_metadata "$OUTPUT"

ir_capture filesystems 30 cat /proc/self/mountinfo
ir_capture disk_usage 30 df -PT
ir_capture inode_usage 30 df -Pi
ir_capture core_dumps 60 coredumpctl list --no-pager
ir_capture immutable_etc 90 lsattr -aR /etc
ir_capture immutable_runtime 90 lsattr -aR /tmp /var/tmp /dev/shm /var/www /srv
ir_capture acl_etc 90 getfacl -R -p /etc
ir_capture acl_web 90 getfacl -R -p /var/www /srv

RECENT="$IR_OUT/recent_bodyfile.tsv"
printf 'path\tsize\tmode\tuid\tgid\tatime_epoch\tmtime_epoch\tctime_epoch\tinode\tdevice\n' > "$RECENT"
for root in /etc /bin /sbin /usr/bin /usr/sbin /usr/local /opt /tmp /var/tmp /dev/shm /var/www /srv /home /root; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -mtime "-$DAYS" -printf '%p\t%s\t%m\t%U\t%G\t%A@\t%T@\t%C@\t%i\t%D\n' 2>/dev/null
done | sed -n '1,100000p' >> "$RECENT"

UNKNOWN="$IR_OUT/unknown_owners.tsv"
printf 'path\tuid\tgid\tmode\tsize\tmtime_epoch\n' > "$UNKNOWN"
for root in /etc /bin /sbin /usr /opt /tmp /var/tmp /dev/shm /var/www /srv /home /root; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -nouser -o -nogroup \) -printf '%p\t%U\t%G\t%m\t%s\t%T@\n' 2>/dev/null
done | sed -n '1,50000p' >> "$UNKNOWN"

BINFMT="$IR_OUT/binfmt_misc.txt"
{
    printf '%s\n' '===== procfs handlers ====='
    for file in /proc/sys/fs/binfmt_misc/*; do
        [ -f "$file" ] || continue
        printf '\n--- %s ---\n' "$file"; sed -n '1,256p' "$file" 2>/dev/null || true
    done
    printf '%s\n' '===== configuration ====='
    find /etc/binfmt.d /run/binfmt.d /usr/lib/binfmt.d -maxdepth 2 -type f -exec sh -c 'for f do printf "\n--- %s ---\n" "$f"; sed -n "1,256p" "$f"; done' sh {} + 2>/dev/null || true
} > "$BINFMT"

ir_finish
