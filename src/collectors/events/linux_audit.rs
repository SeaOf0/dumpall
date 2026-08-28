use std::fs;
use std::path::{Path, PathBuf};

use super::EventWindow;
use crate::collectors::collection_error;
use crate::config::ResolvedRun;
use crate::model::{CollectionError, LinuxEvent, ParseError};

pub const COLLECTOR_SCOPE: &str = "linux_audit";

#[derive(Debug, Default)]
pub struct LinuxAuditCollection {
    pub events: Vec<LinuxEvent>,
    pub parse_errors: Vec<ParseError>,
    pub errors: Vec<CollectionError>,
    pub files_scanned: u64,
    pub lines_seen: u64,
    /// 读取阶段被时间窗口剔除的事件条数（不消耗 max_event_records 配额）。
    pub window_filtered: u64,
}

pub fn collect_linux_audit(resolved: &ResolvedRun) -> LinuxAuditCollection {
    collect_linux_audit_for(&resolved.audit_log_paths, resolved)
}

pub fn collect_linux_audit_for(paths: &[PathBuf], resolved: &ResolvedRun) -> LinuxAuditCollection {
    let mut report = LinuxAuditCollection::default();
    for input in paths {
        collect_input(input, resolved, &mut report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
    report
}

/// journald-only 系统（无 auth.log/secure/audit 文本源，如新版 Kali/Ubuntu）的
/// 认证事件兜底：只读调用 journalctl 导出 auth/authpriv/daemon/syslog/cron
/// 设施日志为标准 syslog 短格式（与 auth.log 行格式一致），供既有解析路径
/// 使用；解析器只识别已知模式，未识别行保留在导出文件中供人工复核。
/// 导出文件写入 events/journal_auth_export.log，容量上限 64MB；
/// 传入 since 时同步收缩 journalctl --since 范围。
#[cfg(unix)]
pub fn export_journald_auth(
    layout: &crate::output::paths::OutputLayout,
    since: Option<&str>,
    errors: &mut Vec<CollectionError>,
) -> Option<PathBuf> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    const MAX_EXPORT_BYTES: u64 = 64 * 1024 * 1024;
    const JOURNAL_STORE_HINTS: [&str; 2] = ["/var/log/journal", "/run/log/journal"];

    let journal_store_exists = JOURNAL_STORE_HINTS
        .iter()
        .any(|hint| std::path::Path::new(hint).is_dir());
    if !journal_store_exists {
        return None;
    }
    let Some(journalctl) = crate::collectors::host_artifacts::which("journalctl") else {
        errors.push(collection_error(
            COLLECTOR_SCOPE,
            "journalctl",
            "discover",
            "no auth/audit text log source exists and journalctl was not found; journald auth events could not be exported",
            Some(
                "Install systemd journalctl or supply --journal-path with an offline export."
                    .to_string(),
            ),
        ));
        return None;
    };

    let target = layout.events_dir.join("journal_auth_export.log");
    let mut command = Command::new(&journalctl);
    command.args([
        "-o",
        "short",
        "--no-pager",
        "SYSLOG_FACILITY=3",
        "SYSLOG_FACILITY=4",
        "SYSLOG_FACILITY=5",
        "SYSLOG_FACILITY=9",
        "SYSLOG_FACILITY=10",
    ]);
    if let Some(since) = since {
        command.arg("--since").arg(since);
    }
    let child = command.stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            errors.push(collection_error(
                COLLECTOR_SCOPE,
                journalctl.display().to_string(),
                "spawn",
                "journalctl could not be started for the auth export",
                Some(error.to_string()),
            ));
            return None;
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let mut file = match fs::File::create(&target) {
        Ok(file) => file,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            errors.push(collection_error(
                COLLECTOR_SCOPE,
                target.display().to_string(),
                "write",
                "journald auth export file could not be created",
                Some(error.to_string()),
            ));
            return None;
        }
    };

    let mut buffer = [0u8; 65536];
    let mut total: u64 = 0;
    let mut truncated = false;
    while let Ok(read) = stdout.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let mut take = read;
        if total + read as u64 > MAX_EXPORT_BYTES {
            take = (MAX_EXPORT_BYTES.saturating_sub(total)) as usize;
            truncated = true;
        }
        if file.write_all(&buffer[..take]).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&target);
            return None;
        }
        total += take as u64;
        if truncated {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
    }
    if !truncated {
        let _ = child.wait();
    }
    if total == 0 {
        let _ = fs::remove_file(&target);
        errors.push(collection_error(
            COLLECTOR_SCOPE,
            "journalctl",
            "export",
            "journalctl produced no auth/authpriv records for export",
            None,
        ));
        return None;
    }
    if truncated {
        errors.push(collection_error(
            COLLECTOR_SCOPE,
            target.display().to_string(),
            "export",
            "journald auth export truncated at the 64MB cap",
            Some(format!("exported bytes: {total}")),
        ));
    }
    Some(target)
}

fn collect_input(path: &Path, resolved: &ResolvedRun, report: &mut LinuxAuditCollection) {
    if !path.exists() {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "discover",
            "audit log path does not exist",
            Some("Verify the auditd/auth log path or rerun with a readable file.".to_string()),
        ));
        return;
    }
    if path.is_file() {
        parse_file(path, resolved, report);
        return;
    }
    if !path.is_dir() {
        return;
    }
    for file in audit_files(path, resolved.safety.max_depth) {
        parse_file(&file, resolved, report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
}

fn parse_file(path: &Path, resolved: &ResolvedRun, report: &mut LinuxAuditCollection) {
    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    let Ok(metadata) = fs::metadata(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "metadata",
            "could not read audit log metadata",
            None,
        ));
        return;
    };
    if metadata.len() > max_bytes {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "preflight",
            format!(
                "event file exceeds max-file-size limit: {} bytes",
                metadata.len()
            ),
            None,
        ));
        return;
    }
    let Ok(file) = fs::File::open(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "read",
            "could not read audit log file",
            None,
        ));
        return;
    };
    report.files_scanned += 1;
    let window = EventWindow::from_resolved(resolved);
    let mut reader = std::io::BufReader::new(file);
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    let mut line_number = 0u64;
    while (report.events.len() as u64) < resolved.max_event_records {
        // read_until + lossy：非 UTF-8 行（GBK 路径/命令行等）不再整行丢失，
        // raw_hash 始终对行字节内容计算，保住证据完整性。
        let decoded =
            match crate::parsers::read_decoded_log_line(&mut reader, &mut buffer) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(_) => {
                    report.parse_errors.push(ParseError {
                        source_file: path.display().to_string(),
                        line_number: line_number + 1,
                        parser_name: "linux_audit".to_string(),
                        message: "could not read audit log line".to_string(),
                        raw_hash: String::new(),
                        raw_sample: None,
                    });
                    break;
                }
            };
        line_number += 1;
        if decoded.text.trim().is_empty() {
            continue;
        }
        report.lines_seen += 1;
        match crate::parsers::auditd::parse_audit_or_auth_line(
            path,
            line_number,
            &decoded.text,
        ) {
            Ok(Some(mut event)) => {
                if resolved.safety.redact {
                    redact_linux_event(&mut event);
                }
                // 窗口外事件边读边剔除且不消耗 max_event_records 配额，
                // 保证事发时段（最新）记录仍能被读到。
                if !window.contains(event.timestamp.as_deref()) {
                    report.window_filtered += 1;
                    continue;
                }
                report.events.push(event);
            }
            Ok(None) => {}
            Err(message) => report.parse_errors.push(ParseError {
                source_file: path.display().to_string(),
                line_number,
                parser_name: "linux_audit".to_string(),
                message,
                raw_hash: decoded.raw_hash,
                raw_sample: Some(if resolved.safety.redact {
                    crate::safety::redact_text(&decoded.text)
                } else {
                    decoded.text.chars().take(200).collect()
                }),
            }),
        }
    }
}

fn audit_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, 0, max_depth, &mut files);
    files
}

fn walk(path: &Path, depth: usize, max_depth: usize, files: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&child, depth + 1, max_depth, files);
        } else if file_type.is_file() && is_probable_audit_file(&child) {
            files.push(child);
        }
    }
}

fn is_probable_audit_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".log")
        || name.ends_with(".txt")
        || name == "auth"
        || name == "secure"
        || name.contains("audit")
        || name.contains("auth")
        || name.contains("secure")
}

fn redact_linux_event(event: &mut LinuxEvent) {
    for field in [
        &mut event.user,
        &mut event.command_line_summary,
        &mut event.object_path,
    ]
    .into_iter()
    .flatten()
    {
        *field = crate::safety::redact_text(field);
    }
}
