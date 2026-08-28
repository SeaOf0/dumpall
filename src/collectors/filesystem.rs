use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use crate::config::ResolvedRun;
use crate::discovery;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::collection_error;

const MAX_FILES_PER_RUN: u64 = 50_000;
const WEB_FILE_HEADER: &str =
    "path,root_path,size_bytes,modified_at,extension,high_risk_extension,double_extension,reason\n";

#[derive(Debug, Default)]
pub struct FilesystemStats {
    pub files_scanned: u64,
    pub middleware_candidates: usize,
    pub web_root_candidates: usize,
    pub log_candidates: usize,
}

#[derive(Debug, Clone, Serialize)]
struct WebFileRow {
    path: String,
    root_path: String,
    size_bytes: u64,
    modified_at: String,
    extension: String,
    high_risk_extension: bool,
    double_extension: bool,
    reason: String,
}

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<FilesystemStats> {
    let discovery = discovery::discover(resolved, layout)?;

    let since = since_system_time(resolved);
    let mut recent = Vec::new();
    let mut suspicious = Vec::new();
    let mut stats = FilesystemStats {
        middleware_candidates: discovery.middleware.len(),
        web_root_candidates: discovery.web_roots.len(),
        log_candidates: discovery.logs.len(),
        ..FilesystemStats::default()
    };

    for row in discovery.web_roots {
        let root = PathBuf::from(row.path);
        if !root.is_dir() {
            continue;
        }
        let mut scan = WebRootScan {
            max_depth: resolved.safety.max_depth,
            since,
            stats: &mut stats,
            recent: &mut recent,
            suspicious: &mut suspicious,
            errors,
        };
        scan_web_root(&root, &root, 0, &mut scan);
    }

    write_web_file_rows(&layout.recent_web_files, &recent)?;
    write_web_file_rows(&layout.suspicious_files, &suspicious)?;
    Ok(stats)
}

fn write_web_file_rows(path: &Path, rows: &[WebFileRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, WEB_FILE_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

struct WebRootScan<'a> {
    max_depth: usize,
    since: Option<SystemTime>,
    stats: &'a mut FilesystemStats,
    recent: &'a mut Vec<WebFileRow>,
    suspicious: &'a mut Vec<WebFileRow>,
    errors: &'a mut Vec<CollectionError>,
}

fn scan_web_root(root: &Path, current: &Path, depth: usize, scan: &mut WebRootScan<'_>) {
    if scan.stats.files_scanned >= MAX_FILES_PER_RUN {
        scan.errors.push(collection_error(
            "filesystem",
            root.display().to_string(),
            "scan_web_root",
            "filesystem scan item limit reached",
            Some(format!("limit={MAX_FILES_PER_RUN}")),
        ));
        return;
    }

    if depth > scan.max_depth {
        return;
    }

    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(error) => {
            scan.errors.push(collection_error(
                "filesystem",
                current.display().to_string(),
                "read_dir",
                "directory could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };

    for entry in entries {
        if scan.stats.files_scanned >= MAX_FILES_PER_RUN {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                scan.errors.push(collection_error(
                    "filesystem",
                    path.display().to_string(),
                    "file_type",
                    "file type could not be read",
                    Some(error.to_string()),
                ));
                continue;
            }
        };

        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            scan_web_root(root, &path, depth + 1, scan);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        scan.stats.files_scanned += 1;
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                scan.errors.push(collection_error(
                    "filesystem",
                    path.display().to_string(),
                    "metadata",
                    "metadata could not be read",
                    Some(error.to_string()),
                ));
                continue;
            }
        };

        let modified = metadata.modified().ok();
        let row = build_file_row(root, &path, metadata.len(), modified);
        if is_recent(modified, scan.since) {
            scan.recent.push(row.clone());
        }
        if row.high_risk_extension || row.double_extension {
            scan.suspicious.push(row);
        }
    }
}

fn build_file_row(
    root: &Path,
    path: &Path,
    size_bytes: u64,
    modified: Option<SystemTime>,
) -> WebFileRow {
    let extension = file_extension(path);
    let high_risk_extension = is_high_risk_extension(&extension);
    let double_extension = has_double_extension(path);
    let mut reasons = Vec::new();
    if high_risk_extension {
        reasons.push("high_risk_extension");
    }
    if double_extension {
        reasons.push("double_extension");
    }
    if reasons.is_empty() {
        reasons.push("recent_change");
    }

    WebFileRow {
        path: path.display().to_string(),
        root_path: root.display().to_string(),
        size_bytes,
        modified_at: modified
            .map(system_time_to_iso)
            .unwrap_or_else(|| "unknown".to_string()),
        extension,
        high_risk_extension,
        double_extension,
        reason: reasons.join(";"),
    }
}

fn is_recent(modified: Option<SystemTime>, since: Option<SystemTime>) -> bool {
    match (modified, since) {
        (Some(modified), Some(since)) => modified >= since,
        (Some(_), None) => true,
        _ => false,
    }
}

fn since_system_time(resolved: &ResolvedRun) -> Option<SystemTime> {
    resolved
        .time_range
        .since
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
        .map(|value| {
            let timestamp = value.unix_timestamp();
            if timestamp >= 0 {
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)
            } else {
                SystemTime::UNIX_EPOCH
            }
        })
}

fn system_time_to_iso(value: SystemTime) -> String {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
            else {
                return "unknown".to_string();
            };
            crate::time_utils::format_iso(datetime)
        }
        Err(_) => "unknown".to_string(),
    }
}

fn file_extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub fn is_high_risk_extension(extension: &str) -> bool {
    matches!(
        extension
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str(),
        "php"
            | "phtml"
            | "phar"
            | "jsp"
            | "jspx"
            | "asp"
            | "aspx"
            | "ashx"
            | "asmx"
            | "war"
            | "jar"
            | "js"
            | "py"
            | "pl"
            | "sh"
            | "bat"
            | "cmd"
            | "ps1"
    )
}

pub fn has_double_extension(path: &Path) -> bool {
    // 非 UTF-8 文件名（GBK 等）经 to_string_lossy 参与判断，不再因
    // to_str 失败直接返回 false 而漏报 jpg.php 类双扩展名可疑文件。
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let final_ext = parts.last().copied().unwrap_or_default();
    let previous_ext = parts.get(parts.len() - 2).copied().unwrap_or_default();
    is_high_risk_extension(final_ext)
        && matches!(
            previous_ext.to_ascii_lowercase().as_str(),
            "jpg" | "jpeg" | "png" | "gif" | "txt" | "pdf" | "ico" | "css"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_high_risk_extensions() {
        assert!(is_high_risk_extension("php"));
        assert!(is_high_risk_extension(".jsp"));
        assert!(is_high_risk_extension("PS1"));
        assert!(!is_high_risk_extension("jpg"));
    }

    #[test]
    fn detects_double_extensions() {
        assert!(has_double_extension(Path::new("avatar.jpg.php")));
        assert!(has_double_extension(Path::new("note.txt.aspx")));
        assert!(!has_double_extension(Path::new("index.php")));
        assert!(!has_double_extension(Path::new("archive.tar.gz")));
    }
}
