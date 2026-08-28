//! 系统范围文件修改时间扫描。
//!
//! --updatetime 只读取文件系统元数据，不读取文件内容。输出命中窗口的文件，
//! 并对常见攻击工具/脚本名称给出提示，供分析人员与进程、日志、持久化证据交叉复核。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::collection_error;

const MAX_SCANNED_FILES: usize = 250_000;
const MAX_RESULT_ROWS: usize = 100_000;
const MAX_ERRORS: usize = 1_000;

#[derive(Debug, Default)]
pub struct UpdatedFilesStats {
    pub files_scanned: u64,
    pub updated_files: usize,
    pub tool_hints: usize,
}

#[derive(Debug, Clone, Serialize)]
struct UpdatedFileRow {
    path: String,
    size_bytes: u64,
    modified_at: String,
    is_executable: bool,
    tool_hint: String,
    reason: String,
}

/// 扫描平台可见的本地文件系统，按 ResolvedRun.time_range 过滤 mtime。
pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<UpdatedFilesStats> {
    let mut stats = UpdatedFilesStats::default();
    let mut rows = Vec::new();
    let (since, until) = time_bounds(resolved);
    let roots = default_roots();
    let result_root = fs::canonicalize(&layout.root).ok();
    let max_depth = resolved.safety.max_depth.saturating_add(4);
    // 限额错误去重：达到上限后不再对每个盘符/目录重复登记，
    // 只在收尾时汇总为一条（含触发次数），避免淹没真实采集错误。
    let mut scan_limit_hits: u64 = 0;
    let mut row_limit_hits: u64 = 0;

    for root in roots {
        if !root.exists() {
            continue;
        }
        let mut stack = vec![(root, 0usize)];
        while let Some((current, depth)) = stack.pop() {
            if stats.files_scanned as usize >= MAX_SCANNED_FILES {
                scan_limit_hits += 1;
                break;
            }
            if is_virtual_directory(&current)
                || is_result_directory(&current, result_root.as_deref())
            {
                continue;
            }
            let entries = match fs::read_dir(&current) {
                Ok(entries) => entries,
                Err(error) => {
                    push_error(
                        errors,
                        &current,
                        "read_dir",
                        "directory could not be read",
                        Some(error.to_string()),
                    );
                    continue;
                }
            };

            for entry in entries.flatten() {
                if stats.files_scanned as usize >= MAX_SCANNED_FILES {
                    scan_limit_hits += 1;
                    break;
                }
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    if depth < max_depth
                        && !is_virtual_directory(&path)
                        && !is_result_directory(&path, result_root.as_deref())
                    {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                stats.files_scanned += 1;
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        push_error(
                            errors,
                            &path,
                            "metadata",
                            "file metadata could not be read",
                            Some(error.to_string()),
                        );
                        continue;
                    }
                };
                let Some(modified) = metadata.modified().ok() else {
                    continue;
                };
                if !in_window(modified, since, until) {
                    continue;
                }
                if rows.len() >= MAX_RESULT_ROWS {
                    row_limit_hits += 1;
                    break;
                }
                let hint = tool_hint(&path).to_string();
                if !hint.is_empty() {
                    stats.tool_hints += 1;
                }
                rows.push(UpdatedFileRow {
                    path: path.display().to_string(),
                    size_bytes: metadata.len(),
                    modified_at: crate::time_utils::system_time_to_iso(modified),
                    is_executable: is_executable(&metadata, &path),
                    reason: if hint.is_empty() {
                        "modified_in_window".to_string()
                    } else {
                        "known_tool_name_hint".to_string()
                    },
                    tool_hint: hint,
                });
                stats.updated_files += 1;
            }
        }
    }

    if scan_limit_hits > 0 {
        push_limit_error(
            errors,
            "filesystem",
            &format!(
                "filesystem file scan limit reached (triggered {scan_limit_hits} time(s); results are partial)"
            ),
        );
    }
    if row_limit_hits > 0 {
        push_limit_error(
            errors,
            "results",
            &format!(
                "updated-file result row limit reached (triggered {row_limit_hits} time(s); results are partial)"
            ),
        );
    }

    rows.sort_by(|left, right| {
        left.modified_at
            .cmp(&right.modified_at)
            .then_with(|| left.path.cmp(&right.path))
    });
    if rows.is_empty() {
        writers::write_text(
            &layout.updated_files,
            "path,size_bytes,modified_at,is_executable,tool_hint,reason\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.updated_files, &rows)?;
    }
    Ok(stats)
}

fn time_bounds(resolved: &ResolvedRun) -> (Option<SystemTime>, Option<SystemTime>) {
    let since = resolved
        .time_range
        .since
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
        .and_then(offset_to_system_time);
    let until = resolved
        .time_range
        .until
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
        .and_then(offset_to_system_time)
        .or_else(|| Some(SystemTime::now()));
    (since, until)
}

fn offset_to_system_time(value: time::OffsetDateTime) -> Option<SystemTime> {
    let seconds = value.unix_timestamp();
    if seconds < 0 {
        return Some(SystemTime::UNIX_EPOCH);
    }
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64))
}

fn in_window(modified: SystemTime, since: Option<SystemTime>, until: Option<SystemTime>) -> bool {
    if let Some(since) = since {
        if modified < since {
            return false;
        }
    }
    if let Some(until) = until {
        if modified > until {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn default_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Windows 盘符枚举：GetLogicalDrives 位掩码替代 A-Z 逐个 exists() 探测
/// （exists() 命中断连网络盘会长时间阻塞），再用 GetDriveTypeW 跳过
/// 可移动盘/光驱/网络盘，只扫本地固定盘与内存盘。
#[cfg(windows)]
fn default_roots() -> Vec<PathBuf> {
    // Win32 稳定 ABI 值（DRIVE_* 常量在 windows-sys 的
    // Win32_System_WindowsProgramming feature 下，本构建未启用，按 SDK 值定义）。
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_REMOTE: u32 = 4;
    const DRIVE_CDROM: u32 = 5;

    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    if mask == 0 {
        return Vec::new();
    }
    let mut roots = Vec::new();
    for bit in 0..32u32 {
        if mask & (1u32 << bit) == 0 {
            continue;
        }
        let letter = char::from_u32(u32::from(b'A') + bit).unwrap_or('A');
        let root_text = format!("{letter}:\\");
        let root_wide: Vec<u16> = root_text.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_wide.as_ptr())
        };
        if matches!(drive_type, DRIVE_REMOVABLE | DRIVE_REMOTE | DRIVE_CDROM) {
            continue;
        }
        roots.push(PathBuf::from(root_text));
    }
    roots
}

#[cfg(not(any(unix, windows)))]
fn default_roots() -> Vec<PathBuf> {
    vec![PathBuf::from(".")]
}

fn is_virtual_directory(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let text = path.to_string_lossy();
        // /var/lib/docker：容器层数据库与 overlay 层，mtime 扫描命中量巨大且
        // 对 Web 入侵取证价值低；排除以保住总扫描配额留给真实文件系统。
        // 需要容器侧证据时由 container 采集器（--container-log-path）覆盖。
        matches!(
            text.as_ref(),
            "/proc" | "/sys" | "/dev" | "/run" | "/var/lib/docker"
        )
    }
    #[cfg(windows)]
    {
        let _ = path;
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

fn is_result_directory(path: &Path, result_root: Option<&Path>) -> bool {
    result_root
        .map(|root| path == root || path.starts_with(root))
        .unwrap_or(false)
}

fn is_executable(metadata: &fs::Metadata, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = path;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| {
                matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "exe" | "com" | "dll" | "sys" | "ps1" | "bat" | "cmd" | "vbs" | "js"
                )
            })
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (metadata, path);
        false
    }
}

fn tool_hint(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    const HINTS: &[(&str, &str)] = &[
        ("psexec", "PsExec"),
        ("psexesvc", "PsExec service"),
        ("mimikatz", "Mimikatz"),
        ("procdump", "ProcDump"),
        ("procmon", "Procmon"),
        ("rclone", "Rclone"),
        ("chisel", "Chisel"),
        ("frpc", "FRP client"),
        ("frps", "FRP server"),
        ("ncat", "Ncat"),
        ("netcat", "Netcat"),
        ("socat", "Socat"),
        ("nc", "Netcat"),
        ("gost", "GOST"),
        ("ngrok", "Ngrok"),
        ("meterpreter", "Meterpreter"),
        ("mshta", "Mshta"),
        ("certutil", "Certutil"),
        ("bitsadmin", "BITSAdmin"),
        ("regsvr32", "Regsvr32"),
        ("rundll32", "Rundll32"),
        ("powershell", "PowerShell"),
        ("pwsh", "PowerShell"),
        ("curl", "Curl"),
        ("wget", "Wget"),
        ("plink", "Plink"),
    ];
    HINTS
        .iter()
        .find(|(needle, _)| {
            name == *needle
                || name.starts_with(&format!("{needle}."))
                || name.starts_with(&format!("{needle}-"))
                || name.starts_with(&format!("{needle}_"))
        })
        .map(|(_, label)| *label)
        .unwrap_or_default()
}

fn push_error(
    errors: &mut Vec<CollectionError>,
    path: &Path,
    operation: &'static str,
    message: &'static str,
    detail: Option<String>,
) {
    if errors.len() < MAX_ERRORS {
        errors.push(collection_error(
            "updated_files",
            path.display().to_string(),
            operation,
            message,
            detail,
        ));
    }
}

fn push_limit_error(errors: &mut Vec<CollectionError>, target: &str, detail: &str) {
    push_error(
        errors,
        Path::new(target),
        "scan_limit",
        "updated-file scan reached a configured limit",
        Some(detail.to_string()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_psexec_and_does_not_match_unrelated_names() {
        assert_eq!(tool_hint(Path::new("PsExec.exe")), "PsExec");
        assert_eq!(tool_hint(Path::new("psexesvc")), "PsExec service");
        assert_eq!(tool_hint(Path::new("my-psexec-not-a-tool")), "");
    }

    #[test]
    fn window_is_inclusive() {
        let now = SystemTime::now();
        assert!(in_window(now, Some(now), Some(now)));
    }
}
