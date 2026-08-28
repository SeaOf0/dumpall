//! 文件系统补充采集：SUID/SGID 文件扫描、临时目录全列、
//! 已删除但仍被进程持有的可执行文件（/proc/*/exe → "(deleted)"）。

use std::fs;
use std::os::unix::fs::MetadataExt;

use serde::Serialize;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::walk_dir_capped;

const SUID_HEADER: &str = "path,setuid,setgid,mode,uid,size,mtime\n";
const TEMP_HEADER: &str = "path,dir,size,mtime\n";
const DELETED_HEADER: &str = "pid,user,exe,cmdline\n";
const FS_ANOMALY_HEADER: &str = "kind,path,detail,size,mtime\n";
const BIN_CHANGE_HEADER: &str = "path,size,mtime\n";
/// 临时目录单目录最大登记条目。
const MAX_TEMP_ROWS: usize = 20_000;
/// 文件系统异常项登记上限（全局可写目录/双扩展伪装/近期大文件）。
const MAX_ANOMALY_ROWS: usize = 5_000;
/// 系统二进制/库目录近期变更登记上限。
const MAX_BIN_CHANGE_ROWS: usize = 10_000;
/// "近期" 判定窗口默认值（30 天）：仅在调用方未提供事件窗口时兜底；
/// 实际窗口由 host_artifacts 调用侧从事件窗口（log_days/--since）派生传入。
pub(crate) const DEFAULT_RECENT_FILE_WINDOW_DAYS: i64 = 30;
/// 近期大文件阈值（疑似打包外泄）。
const LARGE_FILE_BYTES: u64 = 100 * 1024 * 1024;
/// 双扩展伪装：文档扩展名 + 可执行扩展名。
const DOUBLE_EXT_PATTERN: &str = r"\.(jpg|jpeg|png|gif|bmp|txt|pdf|docx?|xlsx?|pptx?|csv|log)\.(php\d?|phtml|jsp|jspx|asp|aspx|exe|sh|bat|bin|ps1|py|pl|rb|so)$";

#[derive(Debug, Clone, Serialize)]
struct SuidRow {
    path: String,
    setuid: String,
    setgid: String,
    mode: String,
    uid: String,
    size: String,
    mtime: String,
}

#[derive(Debug, Clone, Serialize)]
struct TempFileRow {
    path: String,
    dir: String,
    size: String,
    mtime: String,
}

#[derive(Debug, Clone, Serialize)]
struct FsAnomalyRow {
    kind: String,
    path: String,
    detail: String,
    size: String,
    mtime: String,
}

#[derive(Debug, Clone, Serialize)]
struct BinChangeRow {
    path: String,
    size: String,
    mtime: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeletedOpenRow {
    pid: String,
    user: String,
    exe: String,
    cmdline: String,
}

#[derive(Debug, Default)]
pub struct FsExtStats {
    pub files_scanned: u64,
}

const SUID_SCAN_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/opt",
    "/etc",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "/root",
    "/var/www",
    "/srv",
];

const TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/shm"];

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    // 近期文件筛选窗口：None = full_scan 不按时间筛；Some(days) = 只登记
    // 最近 days 天内变更的文件（由调用方从事件窗口派生）。
    recent_window_days: Option<i64>,
) -> Result<FsExtStats> {
    let mut stats = FsExtStats::default();
    let mut failed_dirs = 0usize;
    collect_suid(layout, &mut stats, &mut failed_dirs);
    collect_temp(layout, &mut stats, &mut failed_dirs);
    collect_fs_anomalies(layout, &mut stats, &mut failed_dirs, recent_window_days);
    collect_bin_dir_changes(layout, &mut stats, &mut failed_dirs, recent_window_days);
    if failed_dirs > 0 {
        // 汇总式登记一条，避免逐目录刷屏。
        errors.push(super::collection_error(
            "fs_ext",
            "filesystem scan roots",
            "walk_dir_capped",
            format!(
                "{failed_dirs} director(y/ies) could not be read during filesystem scans (permission or removed mid-scan); those subtrees are not covered"
            ),
            None,
        ));
    }
    collect_deleted_open(layout, resolved, errors)?;
    Ok(stats)
}

fn collect_suid(layout: &OutputLayout, stats: &mut FsExtStats, failed_dirs: &mut usize) {
    let mut rows = Vec::new();
    for root in SUID_SCAN_ROOTS {
        let root_path = std::path::Path::new(root);
        if !root_path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(root_path, |path, is_dir| {
            if is_dir {
                return true;
            }
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.mode();
                if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                    rows.push(SuidRow {
                        path: path.display().to_string(),
                        setuid: (mode & 0o4000 != 0).to_string(),
                        setgid: (mode & 0o2000 != 0).to_string(),
                        mode: format!("{mode:o}"),
                        uid: metadata.uid().to_string(),
                        size: metadata.len().to_string(),
                        mtime: metadata
                            .modified()
                            .ok()
                            .map(crate::time_utils::system_time_to_iso)
                            .unwrap_or_default(),
                    });
                }
            }
            true
        });
        stats.files_scanned += walk_stats.visited as u64;
        *failed_dirs += walk_stats.failed_dirs;
        if !rows.is_empty() && rows.len() > 50_000 {
            break;
        }
    }
    if rows.is_empty() {
        let _ = writers::write_text(&layout.suid_files, SUID_HEADER);
    } else {
        let _ = writers::write_csv_serialize(&layout.suid_files, &rows);
    }
}

fn collect_temp(layout: &OutputLayout, stats: &mut FsExtStats, failed_dirs: &mut usize) {
    let mut rows = Vec::new();
    for dir in TEMP_DIRS {
        let dir_path = std::path::Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(dir_path, |path, is_dir| {
            if rows.len() >= MAX_TEMP_ROWS {
                return false;
            }
            if is_dir {
                return true;
            }
            if let Ok(metadata) = fs::metadata(path) {
                rows.push(TempFileRow {
                    path: path.display().to_string(),
                    dir: (*dir).to_string(),
                    size: metadata.len().to_string(),
                    mtime: metadata
                        .modified()
                        .ok()
                        .map(crate::time_utils::system_time_to_iso)
                        .unwrap_or_default(),
                });
            }
            true
        });
        stats.files_scanned += walk_stats.visited as u64;
        *failed_dirs += walk_stats.failed_dirs;
    }
    if rows.is_empty() {
        let _ = writers::write_text(&layout.temp_files, TEMP_HEADER);
    } else {
        let _ = writers::write_csv_serialize(&layout.temp_files, &rows);
    }
}

fn collect_deleted_open(
    layout: &OutputLayout,
    _resolved: &ResolvedRun,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let mut rows = Vec::new();
    let uid_map = uid_name_map();
    let proc = std::path::Path::new("/proc");
    let Ok(entries) = fs::read_dir(proc) else {
        errors.push(super::collection_error(
            "deleted_open_files",
            "/proc",
            "read_proc",
            "process list could not be read",
            None,
        ));
        return writers::write_text(&layout.deleted_open_files, DELETED_HEADER);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let exe_link = entry.path().join("exe");
        let Ok(target) = fs::read_link(&exe_link) else {
            continue;
        };
        let target = target.to_string_lossy();
        if target.ends_with(" (deleted)") {
            let status = fs::read_to_string(entry.path().join("status")).unwrap_or_default();
            let uid = status
                .lines()
                .find_map(|line| {
                    let rest = line.strip_prefix("Uid:")?;
                    rest.split_whitespace().next().map(|v| v.to_string())
                })
                .unwrap_or_default();
            let cmdline = fs::read_to_string(entry.path().join("cmdline"))
                .map(|content| content.replace('\0', " ").trim().to_string())
                .unwrap_or_default();
            rows.push(DeletedOpenRow {
                pid: name.clone(),
                user: uid_map.get(&uid).cloned().unwrap_or_else(|| uid.clone()),
                exe: target.trim_end_matches(" (deleted)").to_string(),
                cmdline,
            });
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.deleted_open_files, DELETED_HEADER)
    } else {
        writers::write_csv_serialize(&layout.deleted_open_files, &rows)
    }
}

fn uid_name_map() -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                map.insert(fields[2].to_string(), fields[0].to_string());
            }
        }
    }
    map
}

/// 文件系统异常清点：全局可写目录（-perm -0002）、双扩展伪装文件、
/// 近期变更的超大文件（疑似打包外泄）。扫描根覆盖常见可写/业务目录，
/// 逐项受 walk 上限与登记行数上限保护。
/// recent_window_days：None（full_scan）= 不按时间筛；Some(days) = 近 days 天。
fn collect_fs_anomalies(
    layout: &OutputLayout,
    stats: &mut FsExtStats,
    failed_dirs: &mut usize,
    recent_window_days: Option<i64>,
) {
    let mut rows: Vec<FsAnomalyRow> = Vec::new();
    let double_ext = regex::Regex::new(DOUBLE_EXT_PATTERN).ok();
    let cutoff = recent_window_days.map(|days| {
        std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86_400)
    });
    for root in [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/root",
        "/srv",
        "/opt",
        "/var/www",
        "/usr/local",
        "/etc",
    ] {
        if rows.len() >= MAX_ANOMALY_ROWS {
            break;
        }
        let root_path = std::path::Path::new(root);
        if !root_path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(root_path, |path, is_dir| {
            if rows.len() >= MAX_ANOMALY_ROWS {
                return false;
            }
            let Ok(metadata) = fs::metadata(path) else {
                return true;
            };
            let mtime = metadata
                .modified()
                .ok()
                .map(crate::time_utils::system_time_to_iso)
                .unwrap_or_default();
            if is_dir {
                // /tmp 系列目录本身可写属预期，跳过目录本体。
                if metadata.mode() & 0o002 != 0
                    && !matches!(
                        path.to_str(),
                        Some("/tmp" | "/var/tmp" | "/dev/shm" | "/run/shm")
                    )
                {
                    rows.push(FsAnomalyRow {
                        kind: "world_writable_dir".to_string(),
                        path: path.display().to_string(),
                        detail: format!("mode {:o}", metadata.mode()),
                        size: String::new(),
                        mtime,
                    });
                }
                return true;
            }
            let name = path
                .file_name()
                .map(|value| value.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if let Some(pattern) = double_ext.as_ref() {
                if pattern.is_match(&name) {
                    rows.push(FsAnomalyRow {
                        kind: "double_extension".to_string(),
                        path: path.display().to_string(),
                        detail: name,
                        size: metadata.len().to_string(),
                        mtime: mtime.clone(),
                    });
                }
            }
            let is_recent = cutoff
                .map(|boundary| metadata.modified().ok().is_some_and(|t| t > boundary))
                .unwrap_or(true);
            if metadata.len() >= LARGE_FILE_BYTES && is_recent {
                rows.push(FsAnomalyRow {
                    kind: "large_recent_file".to_string(),
                    path: path.display().to_string(),
                    detail: match recent_window_days {
                        Some(days) => format!(">=100MB changed within {days} days"),
                        None => ">=100MB changed recently (full-scan window)".to_string(),
                    },
                    size: metadata.len().to_string(),
                    mtime,
                });
            }
            stats.files_scanned += 1;
            true
        });
        *failed_dirs += walk_stats.failed_dirs;
    }
    if rows.is_empty() {
        let _ = writers::write_text(&layout.fs_anomalies, FS_ANOMALY_HEADER);
    } else {
        let _ = writers::write_csv_serialize(&layout.fs_anomalies, &rows);
    }
}

/// 系统二进制/库目录近期变更文件清点：
/// 覆盖包管理器校验（dpkg -V/rpm -Va）管不到的场景（非包文件、校验库缺失）。
/// recent_window_days：None（full_scan）= 不按时间筛；Some(days) = 近 days 天。
fn collect_bin_dir_changes(
    layout: &OutputLayout,
    stats: &mut FsExtStats,
    failed_dirs: &mut usize,
    recent_window_days: Option<i64>,
) {
    let mut rows: Vec<BinChangeRow> = Vec::new();
    let cutoff = recent_window_days.map(|days| {
        std::time::SystemTime::now() - std::time::Duration::from_secs(days as u64 * 86_400)
    });
    for root in [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
    ] {
        if rows.len() >= MAX_BIN_CHANGE_ROWS {
            break;
        }
        let root_path = std::path::Path::new(root);
        if !root_path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(root_path, |path, is_dir| {
            if is_dir {
                return true;
            }
            if rows.len() >= MAX_BIN_CHANGE_ROWS {
                return false;
            }
            let Ok(metadata) = fs::metadata(path) else {
                return true;
            };
            let is_recent = cutoff
                .map(|boundary| metadata.modified().ok().is_some_and(|t| t > boundary))
                .unwrap_or(true);
            if is_recent {
                rows.push(BinChangeRow {
                    path: path.display().to_string(),
                    size: metadata.len().to_string(),
                    mtime: metadata
                        .modified()
                        .ok()
                        .map(crate::time_utils::system_time_to_iso)
                        .unwrap_or_default(),
                });
                stats.files_scanned += 1;
            }
            true
        });
        *failed_dirs += walk_stats.failed_dirs;
    }
    if rows.is_empty() {
        let _ = writers::write_text(&layout.bin_dir_changes, BIN_CHANGE_HEADER);
    } else {
        let _ = writers::write_csv_serialize(&layout.bin_dir_changes, &rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_declare_expected_columns() {
        assert_eq!(SUID_HEADER.split(',').count(), 7);
        assert_eq!(TEMP_HEADER.split(',').count(), 4);
        assert_eq!(DELETED_HEADER.split(',').count(), 4);
    }
}
