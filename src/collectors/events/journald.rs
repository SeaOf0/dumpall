use std::fs;
use std::path::{Path, PathBuf};

use super::EventWindow;
use crate::collectors::collection_error;
use crate::config::ResolvedRun;
use crate::model::{CollectionError, LinuxEvent, ParseError};

pub const COLLECTOR_SCOPE: &str = "journald";

#[derive(Debug, Default)]
pub struct JournaldCollection {
    pub events: Vec<LinuxEvent>,
    pub parse_errors: Vec<ParseError>,
    pub errors: Vec<CollectionError>,
    pub files_scanned: u64,
    pub lines_seen: u64,
    /// 读取阶段被时间窗口剔除的事件条数（不消耗 max_event_records 配额）。
    pub window_filtered: u64,
}

pub fn collect_journald(resolved: &ResolvedRun) -> JournaldCollection {
    let mut report = JournaldCollection::default();
    for input in &resolved.journal_paths {
        collect_input(input, resolved, &mut report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
    report
}

fn collect_input(path: &Path, resolved: &ResolvedRun, report: &mut JournaldCollection) {
    if !path.exists() {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "discover",
            "journald path does not exist",
            Some(
                "Verify the offline journald export path or rerun with a readable file/directory."
                    .to_string(),
            ),
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
    for file in journal_files(path, resolved.safety.max_depth) {
        parse_file(&file, resolved, report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
}

fn parse_file(path: &Path, resolved: &ResolvedRun, report: &mut JournaldCollection) {
    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    let Ok(metadata) = fs::metadata(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "metadata",
            "could not read journald export metadata",
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
    if is_binary_journal(path) {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "parse",
            "binary journald files are not supported; provide JSON/text export",
            Some("Use journalctl --output=json or --output=short-iso against an offline source before importing.".to_string()),
        ));
        return;
    }
    let Ok(file) = fs::File::open(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "read",
            "could not read journald export file",
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
        // read_until + lossy：非 UTF-8 行不再整行丢失，raw_hash 对行字节内容计算。
        let decoded =
            match crate::parsers::read_decoded_log_line(&mut reader, &mut buffer) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(_) => {
                    report.parse_errors.push(ParseError {
                        source_file: path.display().to_string(),
                        line_number: line_number + 1,
                        parser_name: "journald".to_string(),
                        message: "could not read journald export line".to_string(),
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
        match crate::parsers::journald::parse_journal_line(path, line_number, &decoded.text) {
            Ok(Some(mut event)) => {
                if resolved.safety.redact {
                    redact_linux_event(&mut event);
                }
                // 窗口外事件边读边剔除且不消耗 max_event_records 配额。
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
                parser_name: "journald".to_string(),
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

fn journal_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
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
        } else if file_type.is_file() && is_probable_journal_file(&child) {
            files.push(child);
        }
    }
}

fn is_probable_journal_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.ends_with(".log")
        || name.ends_with(".txt")
        || name.contains("journal")
        || name.contains("systemd")
}

fn is_binary_journal(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("journal"))
        .unwrap_or(false)
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
