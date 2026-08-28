//! Triage 证据副本：把发现项直接引用的文件和用户指定的日志源复制到
//! evidence/suspicious_files/，并用清单记录来源、哈希、大小和复制状态。
//!
//! 这是有界的证据保全，不是磁盘镜像：跳过符号链接和结果目录，限制单文件、
//! 总大小、文件数和目录深度；完整内存仍由显式内存参数单独控制。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::Finding;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const MANIFEST_HEADER: &str = "source_path,relative_path,size_bytes,sha256,mtime,reason,status\n";
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_FILES: usize = 5_000;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_WALK_DEPTH: usize = 8;
/// 目标盘剩余空间低于该值（2GB）即停止复制，避免写满盘拖垮被检服务器。
const MIN_DEST_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 每累计复制该字节数（64MB）复查一次剩余空间。
const DISK_RECHECK_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct EvidenceCopyRow {
    source_path: String,
    relative_path: String,
    size_bytes: String,
    sha256: String,
    mtime: String,
    reason: String,
    status: String,
}

#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    reason: String,
}

/// 仅 triage（或显式使用 triage profile）调用；scan/collect 不复制源文件。
pub fn copy_triage_evidence(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    findings: &[Finding],
) -> Result<String> {
    let mut candidates = BTreeMap::<String, Candidate>::new();

    // 静态扫描和 YARA 的命中路径是最直接的文件证据。
    add_csv_column(
        &layout.suspicious_files,
        "path",
        "static_suspicious",
        &mut candidates,
    );
    add_csv_column(
        &layout.yara_matches,
        "file_path",
        "yara_match",
        &mut candidates,
    );
    add_csv_column(
        &layout.updated_files,
        "path",
        "updated_file",
        &mut candidates,
    );

    // Finding 保存 processes.csv 的行号；用它精确回指可疑进程的可执行文件。
    add_process_executables(&layout.processes, findings, &mut candidates);

    // 发现项中的 source_file 常常就是本地日志/事件文件；只加入实际存在的路径。
    for finding in findings {
        if let Some(source) = finding.source_file.as_deref() {
            add_path(
                Path::new(source),
                format!("finding:{}", finding.category),
                &mut candidates,
            );
        }
    }

    // 用户显式指定的日志、事件、容器和节点证据不能只在解析后留下摘要。
    for (reason, paths) in [
        ("web_log_input", &resolved.log_paths),
        ("db_log_input", &resolved.db_log_paths),
        ("app_log_input", &resolved.app_log_paths),
        ("waf_log_input", &resolved.waf_log_paths),
        ("container_log_input", &resolved.container_log_paths),
        ("k8s_node_input", &resolved.k8s_node_paths),
    ] {
        for path in paths {
            add_path(path, reason, &mut candidates);
        }
    }
    // 默认 EVTX/auth/audit 路径已经由 raw_copy 保全，避免在 evidence/ 下重复复制。
    // 用户显式指定的事件路径仍需作为具体源文件带走。
    let (default_evtx, default_journal, default_audit) =
        crate::config::default_host_event_paths(resolved.profile);
    for (reason, paths, defaults) in [
        ("evtx_input", &resolved.evtx_paths, &default_evtx),
        ("journal_input", &resolved.journal_paths, &default_journal),
        ("audit_input", &resolved.audit_log_paths, &default_audit),
    ] {
        for path in paths {
            if !defaults.iter().any(|default| same_path(path, default)) {
                add_path(path, reason, &mut candidates);
            }
        }
    }

    let mut rows = Vec::new();
    let mut total_bytes = 0u64;
    let mut copied = 0usize;
    let mut skipped = 0usize;
    let mut seen_sources = BTreeSet::new();
    let mut bytes_since_check = 0u64;
    let mut disk_stop: Option<u64> = None;
    // 复制前预检：目标盘不足 2GB 直接停止（空 manifest + Err 登记）。
    if let Some(free) = super::raw_copy::destination_free_bytes(&layout.suspicious_evidence_dir)
    {
        if free < MIN_DEST_FREE_BYTES {
            writers::write_text(&layout.evidence_copy_manifest, MANIFEST_HEADER)?;
            return Err(crate::error::DumpallError::invalid_argument(
                "evidence_copy",
                format!(
                    "destination free space {free} bytes is below the {MIN_DEST_FREE_BYTES}-byte floor; triage evidence copy stopped before starting"
                ),
            ));
        }
    }

    for candidate in candidates.into_values() {
        if copied >= MAX_TOTAL_FILES || total_bytes >= MAX_TOTAL_BYTES {
            skipped += 1;
            continue;
        }
        if disk_stop.is_some() {
            skipped += 1;
            continue;
        }
        // 每累计 64MB 复查目标盘剩余空间，低于 2GB 停止复制（已复制的保留）。
        if bytes_since_check >= DISK_RECHECK_BYTES {
            bytes_since_check = 0;
            if let Some(free) =
                super::raw_copy::destination_free_bytes(&layout.suspicious_evidence_dir)
            {
                if free < MIN_DEST_FREE_BYTES {
                    disk_stop = Some(free);
                    skipped += 1;
                    continue;
                }
            }
        }
        let Ok(source) = canonical_regular_file(&candidate.path) else {
            skipped += 1;
            continue;
        };
        let source_key = source.to_string_lossy().to_string();
        if !seen_sources.insert(source_key) || is_within(&source, &layout.root) {
            continue;
        }
        match copy_one(
            &source,
            layout,
            &candidate.reason,
            &mut rows,
            &mut total_bytes,
        ) {
            CopyOutcome::Copied(bytes) => {
                copied += 1;
                bytes_since_check = bytes_since_check.saturating_add(bytes);
            }
            CopyOutcome::Skipped => skipped += 1,
        }
    }

    if rows.is_empty() {
        writers::write_text(&layout.evidence_copy_manifest, MANIFEST_HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.evidence_copy_manifest, &rows)?;
    }

    let _ = resolved;
    if let Some(free) = disk_stop {
        return Err(crate::error::DumpallError::invalid_argument(
            "evidence_copy",
            format!(
                "destination free space fell to {free} bytes (below the {MIN_DEST_FREE_BYTES}-byte floor) after {copied} file(s) / {total_bytes} bytes; copying stopped, already-copied evidence and manifest retained"
            ),
        ));
    }
    Ok(format!(
        "triage evidence copy completed: {copied} file(s), {total_bytes} bytes, {skipped} skipped (missing, duplicate, or over limit)."
    ))
}

fn add_csv_column(
    path: &Path,
    column: &str,
    reason: &str,
    candidates: &mut BTreeMap<String, Candidate>,
) {
    let Ok(mut reader) = csv::Reader::from_path(path) else {
        return;
    };
    let Ok(headers) = reader.headers().cloned() else {
        return;
    };
    let Some(index) = headers.iter().position(|value| value == column) else {
        return;
    };
    for record in reader.records().flatten() {
        let Some(value) = record
            .get(index)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        add_path(Path::new(value), reason, candidates);
    }
}

fn add_process_executables(
    path: &Path,
    findings: &[Finding],
    candidates: &mut BTreeMap<String, Candidate>,
) {
    let source_file = path.display().to_string();
    let suspicious_lines = findings
        .iter()
        .filter(|finding| {
            finding.source_type == "process"
                && finding.source_file.as_deref() == Some(source_file.as_str())
        })
        .filter_map(|finding| finding.line_number)
        .collect::<BTreeSet<_>>();
    if suspicious_lines.is_empty() {
        return;
    }
    let Ok(mut reader) = csv::Reader::from_path(path) else {
        return;
    };
    let Ok(headers) = reader.headers().cloned() else {
        return;
    };
    let Some(path_index) = headers.iter().position(|value| value == "executable_path") else {
        return;
    };
    for (index, record) in reader.records().flatten().enumerate() {
        let csv_line = index as u64 + 2;
        if !suspicious_lines.contains(&csv_line) {
            continue;
        }
        if let Some(executable) = record
            .get(path_index)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            add_path(
                Path::new(executable),
                "suspicious_process_executable",
                candidates,
            );
        }
    }
}

fn add_path(path: &Path, reason: impl Into<String>, candidates: &mut BTreeMap<String, Candidate>) {
    let reason = reason.into();
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        let mut stack = vec![(path, 0usize)];
        while let Some((current, depth)) = stack.pop() {
            let Ok(entries) = fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let child = entry.path();
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_symlink() {
                    continue;
                }
                if kind.is_file() {
                    add_candidate(child, &reason, candidates);
                } else if kind.is_dir() && depth < MAX_WALK_DEPTH {
                    stack.push((child, depth + 1));
                }
            }
        }
    } else {
        add_candidate(path, &reason, candidates);
    }
}

fn add_candidate(path: PathBuf, reason: &str, candidates: &mut BTreeMap<String, Candidate>) {
    let key = path.to_string_lossy().to_string();
    candidates.entry(key).or_insert_with(|| Candidate {
        path,
        reason: reason.to_string(),
    });
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn canonical_regular_file(path: &Path) -> std::io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    fs::canonicalize(path)
}

fn is_within(path: &Path, root: &Path) -> bool {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    path == root || path.starts_with(&root)
}

enum CopyOutcome {
    Copied(u64),
    Skipped,
}

fn copy_one(
    source: &Path,
    layout: &OutputLayout,
    reason: &str,
    rows: &mut Vec<EvidenceCopyRow>,
    total_bytes: &mut u64,
) -> CopyOutcome {
    let Ok(metadata) = fs::metadata(source) else {
        return CopyOutcome::Skipped;
    };
    let remaining = MAX_TOTAL_BYTES.saturating_sub(*total_bytes);
    if metadata.len() > MAX_FILE_BYTES || metadata.len() > remaining {
        rows.push(EvidenceCopyRow {
            source_path: source.display().to_string(),
            relative_path: String::new(),
            size_bytes: metadata.len().to_string(),
            sha256: String::new(),
            mtime: modified_iso(&metadata),
            reason: reason.to_string(),
            status: "skipped_size_limit".to_string(),
        });
        return CopyOutcome::Skipped;
    }

    let relative = crate::collectors::host_artifacts::raw_copy::sanitize_relative_public(source);
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from("unknown_source")
    } else {
        relative
    };
    let destination = layout.suspicious_evidence_dir.join(relative);
    if let Some(parent) = destination.parent() {
        if fs::create_dir_all(parent).is_err() {
            return CopyOutcome::Skipped;
        }
        restrict_dir(parent);
    }
    let temp = destination.with_extension("part");
    let Ok(mut input) = File::open(source) else {
        return CopyOutcome::Skipped;
    };
    let Ok(mut output) = File::create(&temp) else {
        return CopyOutcome::Skipped;
    };
    restrict_file(&temp);
    let mut hasher = Sha256::new();
    // 1MB 缓冲放堆上:Windows 主线程默认栈仅 1-2MB,栈上大数组会在函数序言
    // 直接撞栈守护页(STATUS_STACK_OVERFLOW 0xc00000fd)。
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut copied = 0u64;
    let ok = loop {
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
    drop(input);
    drop(output);
    if !ok || fs::rename(&temp, &destination).is_err() {
        let _ = fs::remove_file(&temp);
        return CopyOutcome::Skipped;
    }
    restrict_file(&destination);
    *total_bytes += copied;
    rows.push(EvidenceCopyRow {
        source_path: source.display().to_string(),
        relative_path: destination
            .strip_prefix(&layout.root)
            .unwrap_or(&destination)
            .display()
            .to_string(),
        size_bytes: copied.to_string(),
        sha256: format!("{:x}", hasher.finalize()),
        mtime: modified_iso(&metadata),
        reason: reason.to_string(),
        status: "copied".to_string(),
    });
    CopyOutcome::Copied(copied)
}

fn modified_iso(metadata: &fs::Metadata) -> String {
    metadata
        .modified()
        .ok()
        .map(crate::time_utils::system_time_to_iso)
        .unwrap_or_default()
}

fn restrict_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    let _ = path;
}

fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_result_directory() {
        let root = PathBuf::from("/tmp/dumpall-result");
        assert!(is_within(&root.join("evidence/file.txt"), &root));
        assert!(!is_within(Path::new("/var/log/auth.log"), &root));
    }

    #[test]
    fn process_pid_set_is_exact() {
        let mut values = BTreeSet::new();
        values.insert(12_u64);
        assert!(values.contains(&12));
        assert!(!values.contains(&112));
    }

    #[test]
    fn copies_source_and_records_hash() {
        let stamp = crate::time_utils::format_result_stamp(crate::time_utils::now());
        let source = std::env::temp_dir().join(format!("dumpall-evidence-source-{stamp}"));
        let root = std::env::temp_dir().join(format!("dumpall-evidence-out-{stamp}"));
        fs::write(&source, b"evidence").unwrap();
        fs::create_dir_all(&root).unwrap();
        let layout = OutputLayout::from_root(root.clone());
        fs::create_dir_all(&layout.suspicious_evidence_dir).unwrap();
        let mut rows = Vec::new();
        let mut total = 0;
        assert!(matches!(
            copy_one(
                &fs::canonicalize(&source).unwrap(),
                &layout,
                "unit_test",
                &mut rows,
                &mut total
            ),
            CopyOutcome::Copied(_)
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "copied");
        assert_eq!(
            fs::read_to_string(root.join(&rows[0].relative_path)).unwrap(),
            "evidence"
        );
        let _ = fs::remove_file(source);
        let _ = fs::remove_dir_all(root);
    }
}
