pub mod access_log;
pub mod app;
pub mod auditd;
pub mod compressed;
pub mod container_log;
pub mod db;
pub mod evtx;
pub mod iis;
pub mod journald;
pub mod json_log;
pub mod time;
pub mod waf;

use std::collections::HashSet;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{HttpLogEvent, ParseError};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

const MAX_LOG_DISCOVERY_DEPTH: usize = 4;
const MAX_LINE_BYTES: usize = 1024 * 1024;

pub(crate) struct DecodedLogLine {
    pub text: String,
    pub raw_hash: String,
    pub byte_len: usize,
    pub had_invalid_utf8: bool,
    /// 行长度超过上限被截断:内容只保留前 MAX_LINE_BYTES 字节,统计/解析需带截断标记。
    pub was_truncated: bool,
}

#[derive(Debug, Default)]
pub struct ParseReport {
    pub events: usize,
    pub lines_seen: u64,
    pub errors: Vec<ParseError>,
}

pub(crate) fn read_decoded_log_line(
    reader: &mut dyn BufRead,
    buffer: &mut Vec<u8>,
) -> Result<Option<DecodedLogLine>> {
    buffer.clear();
    // 带界单行读取:手工扫描缓冲区找换行,累计超过 MAX_LINE_BYTES 后切换
    // "丢弃模式"读剩余行,内存峰值不超过 MAX_LINE_BYTES + 单次缓冲区大小,
    // 替代无界的 read_until(畸形超长行不能把进程内存吃穿)。
    let mut truncated = false;
    let mut consumed_any = false;
    let mut line_complete = false;
    while !line_complete {
        let (to_consume, found_newline) = {
            let available = match reader.fill_buf() {
                Ok(slice) => slice,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if available.is_empty() {
                (0, false)
            } else {
                match available.iter().position(|byte| *byte == b'\n') {
                    Some(newline) => {
                        if !truncated {
                            append_capped(buffer, &available[..newline], &mut truncated);
                        }
                        (newline + 1, true)
                    }
                    None => {
                        let len = available.len();
                        if !truncated {
                            append_capped(buffer, available, &mut truncated);
                        }
                        (len, false)
                    }
                }
            }
        };
        if to_consume == 0 {
            // EOF:本次调用一个字节都没消费(空行 "\n" 也会消费 1 字节,不会误判)
            break;
        }
        consumed_any = true;
        reader.consume(to_consume);
        if found_newline {
            line_complete = true;
        }
    }

    if !consumed_any {
        return Ok(None);
    }

    while matches!(buffer.last(), Some(b'\n' | b'\r')) {
        buffer.pop();
    }

    let raw_hash = access_log::sha256_hex(buffer);
    let byte_len = buffer.len();
    let had_invalid_utf8 = std::str::from_utf8(buffer).is_err();
    let text = String::from_utf8_lossy(buffer).into_owned();

    Ok(Some(DecodedLogLine {
        text,
        raw_hash,
        byte_len,
        had_invalid_utf8,
        was_truncated: truncated,
    }))
}

/// 追加数据并施加 MAX_LINE_BYTES 上限:超限部分丢弃并置 truncated 标记。
fn append_capped(buffer: &mut Vec<u8>, chunk: &[u8], truncated: &mut bool) {
    if buffer.len() >= MAX_LINE_BYTES {
        *truncated = true;
        return;
    }
    let room = MAX_LINE_BYTES - buffer.len();
    if chunk.len() > room {
        buffer.extend_from_slice(&chunk[..room]);
        *truncated = true;
    } else {
        buffer.extend_from_slice(chunk);
    }
}

pub(crate) fn build_parse_error(
    path: &Path,
    line_number: u64,
    parser_name: &str,
    message: impl Into<String>,
    raw: &str,
    raw_hash: &str,
    redact: bool,
) -> ParseError {
    ParseError {
        source_file: path.display().to_string(),
        line_number,
        parser_name: parser_name.to_string(),
        message: message.into(),
        raw_hash: raw_hash.to_string(),
        raw_sample: Some({
            let sample: String = raw.chars().take(200).collect();
            if redact {
                crate::safety::redact_text(&sample)
            } else {
                sample
            }
        }),
    }
}

pub fn run_log_parsing(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<ParseReport> {
    let candidates = if resolved.mode == crate::model::RunMode::Analyze {
        resolved.log_paths.clone()
    } else {
        discovered_log_paths(&layout.discovered_logs)?
    };

    let files = expand_log_files(
        &candidates,
        resolved.safety.max_depth.min(MAX_LOG_DISCOVERY_DEPTH),
    );
    logger.log(format!("parser: {} log file candidate(s)", files.len()))?;

    let mut report = ParseReport::default();
    let mut events = Vec::new();

    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    for file in files {
        if let Ok(metadata) = fs::metadata(&file) {
            // .gz 按压缩后大小放行,解压侧由 LimitedReader 硬上限兜底
            if metadata.len() > max_bytes {
                report.errors.push(ParseError {
                    source_file: file.display().to_string(),
                    line_number: 0,
                    parser_name: "preflight".to_string(),
                    message: format!(
                        "log file exceeds max-file-size limit: {} bytes",
                        metadata.len()
                    ),
                    raw_hash: access_log::sha256_hex(file.display().to_string().as_bytes()),
                    raw_sample: None,
                });
                continue;
            }
        }
        // 单文件 IO 错误不再上抛中止整个解析阶段:降级为该文件的 ParseError 后继续
        parse_file(&file, resolved.safety.redact, max_bytes, &mut events, &mut report);
    }

    report.events = events.len();
    writers::write_http_events_jsonl(&layout.http_events, &events)?;
    Ok(report)
}

fn discovered_log_paths(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut reader = csv::Reader::from_path(path)?;
    let headers = reader.headers()?.clone();
    let path_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("path"))
        .unwrap_or(0);
    let exists_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("exists"));

    let mut paths = Vec::new();
    for row in reader.records().flatten() {
        let exists = exists_index
            .and_then(|index| row.get(index))
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        if !exists {
            continue;
        }
        if let Some(value) = row.get(path_index) {
            paths.push(PathBuf::from(value));
        }
    }
    Ok(paths)
}

fn expand_log_files(candidates: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for path in candidates {
        expand_one(path, 0, max_depth, &mut seen, &mut files, path.is_file());
    }
    files
}

fn expand_one(
    path: &Path,
    depth: usize,
    max_depth: usize,
    seen: &mut HashSet<String>,
    files: &mut Vec<PathBuf>,
    force_file: bool,
) {
    // 仅 Windows 路径不区分大小写才做 lowercase;Linux 大小写敏感路径误合并会丢文件
    let display = path.display().to_string().replace('\\', "/");
    let key = if cfg!(windows) {
        display.to_ascii_lowercase()
    } else {
        display
    };
    if !seen.insert(key) {
        return;
    }

    if path.is_file() {
        if force_file || is_probable_log_file(path) {
            files.push(path.to_path_buf());
        }
        return;
    }
    if !path.is_dir() || depth >= max_depth {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() || is_probable_log_file(&child) {
            expand_one(&child, depth + 1, max_depth, seen, files, false);
        }
    }
}

fn is_probable_log_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".log")
        || name.ends_with(".txt")
        || name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.ends_with(".gz")
        || name.starts_with("access")
        || name.contains("access_log")
        || name.starts_with("u_ex")
        || name.contains("localhost_access_log")
}

fn parse_file(
    path: &Path,
    redact: bool,
    max_bytes: u64,
    events: &mut Vec<HttpLogEvent>,
    report: &mut ParseReport,
) {
    // 文件级 IO 错误(打开失败/损坏 gzip 流)降级为该文件的 ParseError,保证其余文件继续解析
    let mut reader = match compressed::open_log_reader(path, max_bytes) {
        Ok(reader) => reader,
        Err(error) => {
            report.errors.push(file_level_error(
                path,
                "unknown_access",
                format!("failed to open log file: {error}"),
            ));
            return;
        }
    };
    let mut parser = ParserKind::from_path(path);
    let mut iis_fields: Option<Vec<String>> = None;
    let mut line_buffer = Vec::new();
    let mut line_number = 0_u64;
    // 重探测闸门:仅当本文件尚未成功解析任何事件且已见行数 < 50 时允许换规则,防止抖动
    let mut parsed_in_file = 0_usize;
    let mut non_empty_seen = 0_usize;

    loop {
        let line = match read_decoded_log_line(&mut *reader, &mut line_buffer) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                // 单行读取错误(含损坏 gzip 流)同样降级:记录后停止本文件,继续其余文件
                report.errors.push(file_level_error(
                    path,
                    parser.name(),
                    format!("failed to read log line, stream may be corrupt: {error}"),
                ));
                break;
            }
        };
        line_number += 1;
        // 剥离行首 UTF-8 BOM:避免 JSON 探测走错且粘住
        let text = line.text.strip_prefix('\u{feff}').unwrap_or(&line.text);

        // 超长行:读取层已截断到 MAX_LINE_BYTES,记录 truncated 后仍尝试解析截断内容
        if line.was_truncated {
            let sample = safe_prefix(text, MAX_LINE_BYTES);
            report.errors.push(build_parse_error(
                path,
                line_number,
                parser.name(),
                "line exceeded max line length and was truncated",
                sample,
                &line.raw_hash,
                redact,
            ));
        }
        if text.trim().is_empty() {
            continue;
        }
        non_empty_seen += 1;
        report.lines_seen += 1;
        if line.had_invalid_utf8 {
            report.errors.push(build_parse_error(
                path,
                line_number,
                parser.name(),
                "line contained invalid UTF-8 and was decoded lossily",
                text,
                &line.raw_hash,
                redact,
            ));
        }

        if parser == ParserKind::Unknown
            || (parsed_in_file == 0
                && non_empty_seen < 50
                && matches!(parser, ParserKind::Common | ParserKind::Unknown))
        {
            // 首次成功解析前允许重新探测(BOM/前导噪声导致早期误判时可以纠偏)
            let detected = ParserKind::detect_from_line(text);
            if detected != ParserKind::Unknown {
                parser = detected;
            }
        }
        if parser == ParserKind::Iis && text.starts_with("#Fields:") {
            iis_fields = Some(
                text.trim_start_matches("#Fields:")
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            );
            continue;
        }
        if text.starts_with('#') {
            continue;
        }

        let parsed = match parser {
            ParserKind::Iis => iis::parse_line(path, line_number, text, iis_fields.as_deref()),
            ParserKind::Json => json_log::parse_line(path, line_number, text),
            ParserKind::Common | ParserKind::Unknown => {
                access_log::parse_common_line(path, line_number, text)
            }
        };

        match parsed {
            Ok(mut event) => {
                parsed_in_file += 1;
                if redact {
                    redact_event(&mut event);
                }
                events.push(event);
            }
            Err(message) => report.errors.push(build_parse_error(
                path,
                line_number,
                parser.name(),
                message,
                text,
                &line.raw_hash,
                redact,
            )),
        }
    }
}

/// 文件级错误记录:沿用"raw_hash 取文件路径哈希、raw_sample 置空"的既有约定。
fn file_level_error(path: &Path, parser_name: &str, message: String) -> ParseError {
    ParseError {
        source_file: path.display().to_string(),
        line_number: 0,
        parser_name: parser_name.to_string(),
        message,
        raw_hash: access_log::sha256_hex(path.display().to_string().as_bytes()),
        raw_sample: None,
    }
}

fn safe_prefix(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn redact_event(event: &mut HttpLogEvent) {
    for field in [
        &mut event.uri_query,
        &mut event.referer,
        &mut event.user_agent,
        &mut event.host,
        &mut event.xff_ip,
    ]
    .into_iter()
    .flatten()
    {
        *field = crate::safety::redact_text(field);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserKind {
    Unknown,
    Common,
    Iis,
    Json,
}

impl ParserKind {
    fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.starts_with("u_ex") {
            return Self::Iis;
        }
        Self::Unknown
    }

    fn detect_from_line(line: &str) -> Self {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#Fields:") {
            Self::Iis
        } else if trimmed.starts_with('{') {
            Self::Json
        } else if trimmed.starts_with('#') {
            Self::Unknown
        } else {
            Self::Common
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_access",
            Self::Common => "common_access",
            Self::Iis => "iis_w3c",
            Self::Json => "json_access",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn expands_probable_log_files_only() {
        assert!(is_probable_log_file(Path::new("access.log")));
        assert!(is_probable_log_file(Path::new(
            "localhost_access_log.2026-05-15.txt"
        )));
        assert!(is_probable_log_file(Path::new("u_ex260515.log")));
        assert!(!is_probable_log_file(Path::new("notes.md")));
    }

    #[test]
    fn bounded_line_reader_truncates_overlong_lines() {
        // 畸形超长行:读取层截断到 MAX_LINE_BYTES,后续行仍能继续读取
        let overlong = "x".repeat(MAX_LINE_BYTES + 4096);
        let payload = format!("{overlong}\nnormal line\n");
        let mut reader = Cursor::new(payload.into_bytes());
        let mut buffer = Vec::new();

        let first = read_decoded_log_line(&mut reader, &mut buffer)
            .unwrap()
            .expect("first line present");
        assert!(first.was_truncated);
        assert_eq!(first.byte_len, MAX_LINE_BYTES);
        assert!(first.text.starts_with('x'));

        let second = read_decoded_log_line(&mut reader, &mut buffer)
            .unwrap()
            .expect("second line present");
        assert!(!second.was_truncated);
        assert_eq!(second.text, "normal line");

        assert!(read_decoded_log_line(&mut reader, &mut buffer).unwrap().is_none());
    }

    #[test]
    fn bounded_line_reader_keeps_empty_and_final_lines() {
        // 空行/无换行结尾的最后一行不能被误判为 EOF
        let payload = b"\nlast line without newline".to_vec();
        let mut reader = Cursor::new(payload);
        let mut buffer = Vec::new();

        let empty = read_decoded_log_line(&mut reader, &mut buffer)
            .unwrap()
            .expect("empty line still yields a record");
        assert_eq!(empty.text, "");

        let last = read_decoded_log_line(&mut reader, &mut buffer)
            .unwrap()
            .expect("final line without newline");
        assert_eq!(last.text, "last line without newline");

        assert!(read_decoded_log_line(&mut reader, &mut buffer).unwrap().is_none());
    }

    #[test]
    fn bom_is_stripped_before_format_detection() {
        // BOM 前置时 JSON 探测必须走对:剥离 BOM 后按 '{' 探测为 JSON
        let text = "\u{feff}{\"timestamp\":\"2026-05-15T08:00:00Z\"}";
        let stripped = text.strip_prefix('\u{feff}').unwrap_or(text);
        assert!(matches!(ParserKind::detect_from_line(stripped), ParserKind::Json));
        // BOM 前置的 #Fields 指令探测为 IIS
        let fields = "\u{feff}#Fields: date time c-ip";
        let stripped_fields = fields.strip_prefix('\u{feff}').unwrap_or(fields);
        assert!(matches!(
            ParserKind::detect_from_line(stripped_fields),
            ParserKind::Iis
        ));
    }
}
