#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ir_require_linux

OUTPUT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        -h|--help) printf '用法: %s --output DIR\n' "$0"; exit 0 ;;
        *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
    esac
done
ir_init application_artifacts "$OUTPUT"

OUT="$IR_OUT/application_artifacts.tsv"
printf 'user\tkind\tpath\tsize\tmtime_epoch\tsha256\tnote\n' > "$OUT"
while IFS=: read -r user _ _ _ _ home _; do
    [ -d "$home" ] || continue
    for rel in \
        '.config/google-chrome/Default/History' \
        '.config/chromium/Default/History' \
        '.config/BraveSoftware/Brave-Browser/Default/History' \
        '.config/microsoft-edge/Default/History' \
        '.mozilla/firefox/profiles.ini' \
        '.local/share/recently-used.xbel' \
        '.local/share/fish/fish_history' \
        '.python_history' '.mysql_history' '.psql_history' '.sqlite_history' \
        '.config/rclone/rclone.conf' '.config/anydesk/service.conf' \
        '.config/rustdesk/RustDesk.toml' '.config/TeamViewer/client.conf' \
        '.aws/config' '.azure/azureProfile.json' '.kube/config'; do
        path="$home/$rel"; [ -f "$path" ] || continue
        size="$(stat -c '%s' "$path" 2>/dev/null || printf 0)"
        mtime="$(stat -c '%Y' "$path" 2>/dev/null || printf '')"
        hash=""; [ "$size" -le 67108864 ] && hash="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
        kind="metadata"; note="content_not_copied"
        case "$rel" in *History|*places.sqlite|*recently-used.xbel) kind="user_activity" ;; *anydesk*|*rustdesk*|*TeamViewer*) kind="remote_access" ;; *.aws/*|*.azure/*|*.kube/*|*rclone*) kind="cloud_or_transfer" ;; esac
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$kind" "$path" "$size" "$mtime" "$hash" "$note" >> "$OUT"
    done
    find "$home/.mozilla/firefox" -maxdepth 3 -type f \( -name places.sqlite -o -name downloads.sqlite \) -print 2>/dev/null | sed -n '1,100p' | while IFS= read -r path; do
        [ -f "$path" ] || continue
        size="$(stat -c '%s' "$path" 2>/dev/null || printf 0)"; mtime="$(stat -c '%Y' "$path" 2>/dev/null || printf '')"
        hash=""; [ "$size" -le 67108864 ] && hash="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
        printf '%s\tuser_activity\t%s\t%s\t%s\t%s\tcontent_not_copied\n' "$user" "$path" "$size" "$mtime" "$hash" >> "$OUT"
    done
done < /etc/passwd

for path in /etc/anydesk/* /var/log/anydesk* /var/log/teamviewer* /var/log/rustdesk* /root/.config/rclone/rclone.conf; do
    [ -f "$path" ] || continue
    size="$(stat -c '%s' "$path" 2>/dev/null || printf 0)"; mtime="$(stat -c '%Y' "$path" 2>/dev/null || printf '')"
    hash=""; [ "$size" -le 67108864 ] && hash="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
    printf 'root\tremote_access_or_transfer\t%s\t%s\t%s\t%s\tcontent_not_copied\n' "$path" "$size" "$mtime" "$hash" >> "$OUT"
done

ir_capture docker_info 45 docker info
ir_capture docker_containers 45 docker ps -a --no-trunc
ir_capture containerd_namespaces 45 ctr namespaces list
ir_capture kubernetes_pods 45 crictl pods
ir_capture kubernetes_containers 45 crictl ps -a
ir_finish
