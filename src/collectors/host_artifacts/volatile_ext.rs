//! Linux volatile context that complements the basic process list.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::Digest;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const PROCESS_HEADER: &str = "pid,ppid,uid,exe,exe_sha256,cwd,root,cgroup,mount_ns,pid_ns,net_ns,user_ns,fd_count,deleted_fd_count,memfd_count,socket_fd_count,suspicious_fd_targets\n";
const BINFMT_HEADER: &str = "entry,enabled,interpreter,flags,offset,magic,mask,raw\n";
const CORE_HEADER: &str = "path,size,uid,mode,mtime,source\n";
const MAX_PROCESSES: usize = 4096;
const MAX_FDS_TOTAL: usize = 100_000;
const MAX_FD_DETAIL_CHARS: usize = 4096;
const MAX_HASH_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CORE_ROWS: usize = 5000;

#[derive(Debug, Serialize)]
struct ProcessExtendedRow {
    pid: String,
    ppid: String,
    uid: String,
    exe: String,
    exe_sha256: String,
    cwd: String,
    root: String,
    cgroup: String,
    mount_ns: String,
    pid_ns: String,
    net_ns: String,
    user_ns: String,
    fd_count: usize,
    deleted_fd_count: usize,
    memfd_count: usize,
    socket_fd_count: usize,
    suspicious_fd_targets: String,
}

#[derive(Debug, Serialize)]
struct BinfmtRow {
    entry: String,
    enabled: String,
    interpreter: String,
    flags: String,
    offset: String,
    magic: String,
    mask: String,
    raw: String,
}

#[derive(Debug, Serialize)]
struct CoreDumpRow {
    path: String,
    size: u64,
    uid: u32,
    mode: String,
    mtime: String,
    source: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_process_extended(layout, errors)?;
    collect_binfmt(layout)?;
    collect_core_dumps(layout)?;
    Ok(())
}

fn collect_process_extended(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let output = layout.collection_dir.join("process_extended.csv");
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(super::collection_error(
                "process_extended",
                "/proc",
                "read_dir",
                "extended process context could not enumerate procfs",
                Some(error.to_string()),
            ));
            return writers::write_text(&output, PROCESS_HEADER);
        }
    };
    let mut proc_dirs = entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            Some((pid, entry.path()))
        })
        .collect::<Vec<_>>();
    let total_processes = proc_dirs.len();
    // PID 降序（新进程优先）后再截断：按升序截断会系统性丢弃最新进程，
    // 而最新进程恰恰是入侵排查最关心的对象。
    proc_dirs.sort_by(|a, b| b.0.cmp(&a.0));
    proc_dirs.truncate(MAX_PROCESSES);
    if total_processes > MAX_PROCESSES {
        errors.push(super::collection_error(
            "process_extended",
            "/proc",
            "process_cap",
            format!(
                "process count {total_processes} exceeded the {MAX_PROCESSES} row cap; retained the highest PIDs (newest-first), {dropped} lower-PID process(es) omitted",
                dropped = total_processes - MAX_PROCESSES
            ),
            None,
        ));
    }

    let mut rows = Vec::new();
    let mut hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut fds_seen = 0usize;
    let mut fds_exhausted = false;
    for (pid, proc_dir) in proc_dirs {
        let status = fs::read_to_string(proc_dir.join("status")).unwrap_or_default();
        let exe_path = fs::read_link(proc_dir.join("exe")).ok();
        let exe = exe_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let exe_sha256 = exe_path
            .as_ref()
            .map(|path| {
                hashes
                    .entry(path.clone())
                    .or_insert_with(|| hash_file_capped(path))
                    .clone()
            })
            .unwrap_or_default();
        let mut fd_count = 0usize;
        let mut deleted_fd_count = 0usize;
        let mut memfd_count = 0usize;
        let mut socket_fd_count = 0usize;
        let mut suspicious = Vec::new();
        if fds_seen < MAX_FDS_TOTAL {
            if let Ok(fds) = fs::read_dir(proc_dir.join("fd")) {
                for fd in fds.flatten() {
                    if fds_seen >= MAX_FDS_TOTAL {
                        // fd 总量耗尽：后续进程 fd_count 记 0，需显式登记避免误读。
                        fds_exhausted = true;
                        break;
                    }
                    fds_seen += 1;
                    fd_count += 1;
                    let target = fs::read_link(fd.path())
                        .map(|path| path.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let lower = target.to_ascii_lowercase();
                    deleted_fd_count += usize::from(lower.contains(" (deleted)"));
                    memfd_count += usize::from(lower.contains("memfd:"));
                    socket_fd_count += usize::from(lower.starts_with("socket:["));
                    if lower.contains(" (deleted)")
                        || lower.contains("memfd:")
                        || lower.starts_with("/dev/shm/")
                        || lower.starts_with("/tmp/")
                    {
                        suspicious.push(format!(
                            "{}->{}",
                            fd.file_name().to_string_lossy(),
                            target
                        ));
                    }
                }
            }
        }
        let mut suspicious_fd_targets = suspicious.join(" | ");
        truncate_string(&mut suspicious_fd_targets, MAX_FD_DETAIL_CHARS);
        rows.push(ProcessExtendedRow {
            pid: pid.to_string(),
            ppid: status_field(&status, "PPid"),
            uid: status_field(&status, "Uid"),
            exe,
            exe_sha256,
            cwd: read_link_text(proc_dir.join("cwd")),
            root: read_link_text(proc_dir.join("root")),
            cgroup: fs::read_to_string(proc_dir.join("cgroup"))
                .map(|value| value.replace('\n', " | "))
                .unwrap_or_default(),
            mount_ns: read_link_text(proc_dir.join("ns/mnt")),
            pid_ns: read_link_text(proc_dir.join("ns/pid")),
            net_ns: read_link_text(proc_dir.join("ns/net")),
            user_ns: read_link_text(proc_dir.join("ns/user")),
            fd_count,
            deleted_fd_count,
            memfd_count,
            socket_fd_count,
            suspicious_fd_targets,
        });
    }
    if fds_exhausted {
        errors.push(super::collection_error(
            "process_extended",
            "/proc/*/fd",
            "fd_cap",
            format!(
                "total fd enumeration reached the {MAX_FDS_TOTAL} cap; fd counts for the remaining (lower-PID) processes are recorded as 0 and their fd evidence was not collected"
            ),
            None,
        ));
    }
    if rows.is_empty() {
        writers::write_text(&output, PROCESS_HEADER)
    } else {
        writers::write_csv_serialize(&output, &rows)
    }
}

fn collect_binfmt(layout: &OutputLayout) -> Result<()> {
    let output = layout.collection_dir.join("binfmt_misc.csv");
    let root = Path::new("/proc/sys/fs/binfmt_misc");
    let mut rows = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "register" || name == "status" {
                continue;
            }
            let Ok(raw) = fs::read_to_string(entry.path()) else {
                continue;
            };
            rows.push(BinfmtRow {
                entry: name,
                enabled: raw.lines().next().unwrap_or_default().to_string(),
                interpreter: prefixed_value(&raw, "interpreter "),
                flags: prefixed_value(&raw, "flags: "),
                offset: prefixed_value(&raw, "offset "),
                magic: prefixed_value(&raw, "magic "),
                mask: prefixed_value(&raw, "mask "),
                raw: raw.replace('\n', " | "),
            });
        }
    }
    if rows.is_empty() {
        writers::write_text(&output, BINFMT_HEADER)
    } else {
        writers::write_csv_serialize(&output, &rows)
    }
}

fn collect_core_dumps(layout: &OutputLayout) -> Result<()> {
    let output = layout.collection_dir.join("core_dumps.csv");
    let mut rows = Vec::new();
    for root in ["/var/lib/systemd/coredump", "/var/crash"] {
        let root_path = Path::new(root);
        let Ok(entries) = fs::read_dir(root_path) else {
            continue;
        };
        for entry in entries.flatten() {
            if rows.len() >= MAX_CORE_ROWS {
                break;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            rows.push(CoreDumpRow {
                path: path.display().to_string(),
                size: metadata.len(),
                uid: metadata.uid(),
                mode: format!("{:o}", metadata.mode()),
                mtime: metadata
                    .modified()
                    .ok()
                    .map(crate::time_utils::system_time_to_iso)
                    .unwrap_or_default(),
                source: root.to_string(),
            });
        }
    }
    if rows.is_empty() {
        writers::write_text(&output, CORE_HEADER)
    } else {
        writers::write_csv_serialize(&output, &rows)
    }
}

fn hash_file_capped(path: &Path) -> String {
    let Ok(metadata) = fs::metadata(path) else {
        return String::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_HASH_FILE_BYTES {
        return String::new();
    }
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let mut hasher = sha2::Sha256::new();
    // 1MB 缓冲放堆上:Windows 主线程默认栈仅 1-2MB,栈上大数组会在函数序言
    // 直接撞栈守护页(STATUS_STACK_OVERFLOW 0xc00000fd)。
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let Ok(read) = file.read(&mut buffer) else {
            return String::new();
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}

fn status_field(status: &str, key: &str) -> String {
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == key).then(|| {
                value
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .unwrap_or_default()
}

fn read_link_text(path: PathBuf) -> String {
    fs::read_link(path)
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn prefixed_value(raw: &str, prefix: &str) -> String {
    raw.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::to_string))
        .unwrap_or_default()
}

fn truncate_string(value: &mut String, max: usize) {
    if value.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str("...(truncated)");
}
