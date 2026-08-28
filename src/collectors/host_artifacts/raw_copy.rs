//! 原始证据副本：把关键原始文件（系统日志、配置、crontab、authorized_keys 等）
//! 复制进结果目录 raw/ 并生成哈希清单，供分析机二次复检。
//!
//! 上限：单文件 256 MB、总数 10_000、总量 2 GiB；复制前与每累计 64MB 复查
//! 目标盘剩余空间，低于 2GB 停止复制（已复制的保留并登记停止原因）。

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::Digest;

use crate::config::ResolvedRun;
use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;
use crate::output::writers;

const MANIFEST_HEADER: &str = "source_path,relative_path,size,sha256,mtime\n";
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_FILES: usize = 10_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 目标盘剩余空间低于该值（2GB）即停止复制，避免写满盘拖垮被检服务器。
const MIN_DEST_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 每累计复制该字节数（64MB）复查一次剩余空间。
const DISK_RECHECK_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct RawManifestRow {
    source_path: String,
    relative_path: String,
    size: String,
    sha256: String,
    mtime: String,
}

#[cfg(unix)]
const RAW_CANDIDATES: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudo.conf",
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/rc.local",
    "/etc/rc.d/rc.local",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/ssh/sshd_config.d",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/environment",
    "/etc/security/pam_env.conf",
    "/etc/motd",
    "/etc/update-motd.d",
    "/etc/skel",
    "/var/spool/cron",
    "/var/spool/cron/atspool",
    "/var/spool/at",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/run/systemd/system",
    "/etc/binfmt.d",
    "/run/binfmt.d",
    "/usr/lib/binfmt.d",
    "/etc/udev/rules.d",
    "/etc/pam.d",
    "/etc/audit",
    "/etc/ld.so.conf.d",
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d",
    "/etc/yum.repos.d",
    "/etc/modprobe.d",
    "/etc/modules",
    "/etc/docker",
    "/etc/containerd",
    "/etc/kubernetes",
    "/run/log/journal",
    "/var/log/journal",
    "/var/crash",
    "/var/lib/systemd/coredump",
    "/var/log",
];

#[cfg(windows)]
fn windows_raw_candidates() -> Vec<PathBuf> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let paths = vec![
        system_root.join(r"System32\drivers\etc\hosts"),
        system_root.join(r"System32\winevt\Logs"),
        system_root.join(r"System32\Tasks"),
        system_root.join("Tasks"),
        system_root.join("Prefetch"),
        system_root.join(r"AppCompat\Programs\Amcache.hve"),
        system_root.join(r"System32\sru\SRUDB.dat"),
        system_root.join(r"appcompat\pca"),
        system_root.join(r"System32\LogFiles\Firewall"),
        system_root.join(r"System32\LogFiles\SUM"),
        system_root.join(r"INF\setupapi.dev.log"),
        program_data.join(r"Microsoft\Windows\WER\ReportArchive"),
        program_data.join(r"Microsoft\Windows\WER\ReportQueue"),
        program_data.join(r"Microsoft\Windows Defender\Support"),
        program_data.join(r"Microsoft\Windows Defender\Scans\History\Service"),
        // 本地事件查看器"自定义视图"定义（XML 查询，含系统级与各用户级）。
        system_root.join(r"System32\winevt\Views"),
    ];
    paths
}

/// 目标目录所在磁盘剩余空间（字节）。unix 经 PATH 白名单 df -B1（回退 -k），
/// windows 用 GetDiskFreeSpaceExW；查询失败返回 None（调用方退化为无门限）。
pub(crate) fn destination_free_bytes(directory: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let df = super::which("df")?;
        for (args, unit) in [(vec!["-B1", "-P"], 1u64), (vec!["-k", "-P"], 1024u64)] {
            let output = std::process::Command::new(&df)
                .args(&args)
                .arg(directory)
                .output()
                .ok()?;
            if !output.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let line = text.lines().nth(1)?;
            // -P 保证单行；可用空间是第 4 列。
            let available = line.split_whitespace().nth(3)?.parse::<u64>().ok()?;
            return Some(available.saturating_mul(unit));
        }
        None
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = directory
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut free: u64 = 0;
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            Some(free)
        } else {
            None
        }
    }
}

/// 复制进度与磁盘门限状态：触发停止时记录当时剩余空间（写入 manifest 后
/// 以 Err 上报，由调用方登记为 CollectionError；已复制文件全部保留）。
struct CopyState {
    total_bytes: u64,
    skipped: usize,
    copied_rows: usize,
    bytes_since_check: u64,
    disk_stop: Option<u64>,
}

impl CopyState {
    fn new() -> Self {
        Self {
            total_bytes: 0,
            skipped: 0,
            copied_rows: 0,
            bytes_since_check: 0,
            disk_stop: None,
        }
    }

    fn limits_reached(&self) -> bool {
        self.copied_rows >= MAX_TOTAL_FILES || self.total_bytes >= MAX_TOTAL_BYTES
    }

    /// 复制前检查：已达文件/字节上限，或自上次复查后累计 ≥64MB 时复查剩余空间。
    fn pre_copy_check(&mut self, destination_root: &Path) {
        if self.disk_stop.is_some() || self.limits_reached() {
            return;
        }
        if self.bytes_since_check >= DISK_RECHECK_BYTES {
            self.bytes_since_check = 0;
            if let Some(free) = destination_free_bytes(destination_root) {
                if free < MIN_DEST_FREE_BYTES {
                    self.disk_stop = Some(free);
                }
            }
        }
    }

    fn record_copied(&mut self, bytes: u64) {
        self.total_bytes += bytes;
        self.bytes_since_check = self.bytes_since_check.saturating_add(bytes);
        self.copied_rows += 1;
    }
}

pub fn copy_raw_evidence(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<String> {
    let mut rows = Vec::new();
    let mut state = CopyState::new();
    // 复制前预检：目标盘不足 2GB 直接停止（空 manifest + Err 登记）。
    if let Some(free) = destination_free_bytes(&layout.raw_dir) {
        if free < MIN_DEST_FREE_BYTES {
            writers::write_text(&layout.raw_manifest, MANIFEST_HEADER)?;
            return Err(DumpallError::invalid_argument(
                "raw_copy",
                format!(
                    "destination free space {free} bytes is below the {MIN_DEST_FREE_BYTES}-byte floor; raw evidence copy stopped before starting"
                ),
            ));
        }
    }
    #[cfg(unix)]
    let candidates: Vec<PathBuf> = RAW_CANDIDATES.iter().map(PathBuf::from).collect();
    #[cfg(windows)]
    let candidates = windows_raw_candidates();
    for path in candidates {
        if state.limits_reached() || state.disk_stop.is_some() {
            state.skipped += 1;
            continue;
        }
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            copy_dir_candidate(&path, layout, &mut rows, &mut state);
        } else {
            state.pre_copy_check(&layout.raw_dir);
            if state.disk_stop.is_some() {
                state.skipped += 1;
                continue;
            }
            copy_one_file(&path, layout, &mut rows, &mut state);
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.raw_manifest, MANIFEST_HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.raw_manifest, &rows)?;
    }
    let _ = resolved;
    if let Some(free) = state.disk_stop {
        return Err(DumpallError::invalid_argument(
            "raw_copy",
            format!(
                "destination free space fell to {free} bytes (below the {MIN_DEST_FREE_BYTES}-byte floor) after {} file(s) / {} bytes; copying stopped, already-copied evidence and manifest retained",
                state.copied_rows, state.total_bytes
            ),
        ));
    }
    Ok(format!(
        "raw evidence copy completed: {} file(s), {} bytes, {} skipped (missing or over limit).",
        state.copied_rows,
        state.total_bytes,
        state.skipped
    ))
}

fn copy_dir_candidate(
    dir: &Path,
    layout: &OutputLayout,
    rows: &mut Vec<RawManifestRow>,
    state: &mut CopyState,
) {
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((current, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            state.skipped += 1;
            continue;
        };
        for entry in entries.flatten() {
            if state.limits_reached() || state.disk_stop.is_some() {
                state.skipped += 1;
                return;
            }
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if depth < 8 {
                    stack.push((path, depth + 1));
                }
            } else if kind.is_file() {
                state.pre_copy_check(&layout.raw_dir);
                if state.disk_stop.is_some() {
                    state.skipped += 1;
                    return;
                }
                copy_one_file(&path, layout, rows, state);
            }
        }
    }
}

fn copy_one_file(
    source: &Path,
    layout: &OutputLayout,
    rows: &mut Vec<RawManifestRow>,
    state: &mut CopyState,
) {
    let Ok(metadata) = fs::metadata(source) else {
        state.skipped += 1;
        return;
    };
    let remaining = MAX_TOTAL_BYTES.saturating_sub(state.total_bytes);
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || metadata.len() > remaining {
        state.skipped += 1;
        return;
    }
    let relative = sanitize_relative(source);
    let destination = layout.raw_dir.join(&relative);
    if let Some(parent) = destination.parent() {
        let _ = fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let temp = destination.with_extension("part");
    let Ok(mut input) = File::open(source) else {
        state.skipped += 1;
        return;
    };
    let Ok(mut output) = File::create(&temp) else {
        state.skipped += 1;
        return;
    };
    let mut hasher = sha2::Sha256::new();
    // 1MB 缓冲放堆上:Windows 主线程默认栈仅 1-2MB,栈上大数组会在函数序言
    // 直接撞栈守护页(STATUS_STACK_OVERFLOW 0xc00000fd)。
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut copied = 0u64;
    let copy_ok = loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(_) => break false,
        };
        if read == 0 {
            break true;
        }
        if copied.saturating_add(read as u64) > MAX_FILE_BYTES
            || copied.saturating_add(read as u64) > remaining
        {
            break false;
        }
        if output.write_all(&buffer[..read]).is_err() {
            break false;
        }
        hasher.update(&buffer[..read]);
        copied += read as u64;
    };
    drop(output);
    drop(input);
    if !copy_ok || fs::rename(&temp, &destination).is_err() {
        let _ = fs::remove_file(&temp);
        state.skipped += 1;
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&destination, fs::Permissions::from_mode(0o600));
    }
    let hash = format!("{:x}", hasher.finalize());
    state.record_copied(copied);
    rows.push(RawManifestRow {
        source_path: source.display().to_string(),
        relative_path: relative.display().to_string(),
        size: copied.to_string(),
        sha256: hash,
        mtime: metadata
            .modified()
            .ok()
            .map(crate::time_utils::system_time_to_iso)
            .unwrap_or_default(),
    });
}

/// 把绝对路径转成 raw/ 下的相对路径：去掉盘符/根前缀，分隔符统一为 '/'。
pub(crate) fn sanitize_relative_public(path: &Path) -> PathBuf {
    sanitize_relative(path)
}

fn sanitize_relative(path: &Path) -> PathBuf {
    let text = path.display().to_string();
    let stripped = text.trim_start_matches('/').trim_start_matches('\\');
    let stripped = strip_drive_prefix(stripped);
    let parts: Vec<String> = stripped
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .map(|part| part.replace(':', "_"))
        .collect();
    PathBuf::from(parts.join("/"))
}

fn strip_drive_prefix(path: &str) -> &str {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        &path[2..]
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_relative_paths() {
        assert_eq!(
            sanitize_relative(Path::new("/var/log/auth.log")),
            PathBuf::from("var/log/auth.log")
        );
        assert_eq!(
            sanitize_relative(Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts")),
            PathBuf::from("Windows/System32/drivers/etc/hosts")
        );
    }

    #[test]
    fn rejects_traversal_parts() {
        // 不做路径解析，仅剔除危险段：结果中不允许出现 ".."。
        let relative = sanitize_relative(Path::new("/etc/../etc/passwd"));
        let text = relative.display().to_string();
        assert!(!text.split('/').any(|part| part == ".."));
    }
}
