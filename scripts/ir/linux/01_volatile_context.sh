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
ir_init volatile_context "$OUTPUT"

ir_capture system 30 uname -a
ir_capture uptime 30 uptime
ir_capture memory 30 cat /proc/meminfo
ir_capture cpu 30 cat /proc/cpuinfo
ir_capture mounts 45 findmnt -A -o TARGET,SOURCE,FSTYPE,OPTIONS
ir_capture block_devices 45 lsblk -a -O
ir_capture processes 45 ps -eo pid,ppid,user,lstart,etimes,stat,pcpu,pmem,args
ir_capture process_tree 45 ps -ef --forest
ir_capture sockets 45 ss -H -a -n -p -e -m
ir_capture routes 30 ip -details route show table all
ir_capture rules 30 ip -details rule show
ir_capture neighbors 30 ip -details neigh show
ir_capture addresses 30 ip -details address show
ir_capture links 30 ip -details link show
ir_capture namespaces 45 lsns --output NS,TYPE,PATH,NPROCS,PID,USER,COMMAND
ir_capture systemd_units 60 systemctl list-units --all --no-pager --no-legend
ir_capture systemd_timers 60 systemctl list-timers --all --no-pager
ir_capture dmesg 60 dmesg --ctime
ir_capture journal_boots 30 journalctl --list-boots --no-pager
ir_capture nft_rules 60 nft list ruleset
ir_capture iptables_rules 60 iptables-save
ir_capture bpf_programs 45 bpftool -j prog show
ir_capture bpf_maps 45 bpftool -j map show
ir_capture bpf_links 45 bpftool -j link show
ir_capture keyrings 30 keyctl show
ir_capture open_files 90 lsof -nP

PROC_OUT="$IR_OUT/procfs_snapshot.txt"
(
    blocks=$((IR_MAX_OUTPUT_BYTES / 512)); ulimit -f "$blocks" 2>/dev/null || true
    count=0
    for proc_dir in /proc/[0-9]*; do
        [ -d "$proc_dir" ] || continue
        count=$((count + 1)); [ "$count" -le 4096 ] || break
        pid="${proc_dir#/proc/}"
        printf '\n===== PID %s =====\n' "$pid"
        printf 'exe='; readlink "$proc_dir/exe" 2>/dev/null || true
        printf 'cwd='; readlink "$proc_dir/cwd" 2>/dev/null || true
        printf 'root='; readlink "$proc_dir/root" 2>/dev/null || true
        printf 'cmdline='; tr '\000' ' ' < "$proc_dir/cmdline" 2>/dev/null || true; printf '\n'
        for item in status cgroup limits mountinfo maps; do
            [ -r "$proc_dir/$item" ] || continue
            printf '%s:\n' "$item"
            sed -n '1,4096p' "$proc_dir/$item" 2>/dev/null || true
        done
        printf 'namespaces:\n'; find "$proc_dir/ns" -maxdepth 1 -type l -exec ls -l {} \; 2>/dev/null || true
        printf 'fds:\n'; find "$proc_dir/fd" -maxdepth 1 -type l -exec ls -l {} \; 2>/dev/null | sed -n '1,4096p' || true
    done
) > "$PROC_OUT" 2>&1 || true
printf 'procfs_snapshot\t%s\t%s\t0\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$PROC_OUT" >> "$IR_STATUS"

ir_finish
