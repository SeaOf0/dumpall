use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{AppLogEvent, ParseError, RunMode};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use super::ParseReport;

const MAX_APP_DISCOVERY_DEPTH: usize = 4;
const MAX_LINE_BYTES: usize = 1024 * 1024;

pub fn run_app_log_parsing(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<ParseReport> {
    if !resolved.app_log_paths.is_empty() {
        write_manual_candidates(&layout.discovered_app_logs, &resolved.app_log_paths)?;
    }

    let candidates = if !resolved.app_log_paths.is_empty() {
        resolved.app_log_paths.clone()
    } else if resolved.mode == RunMode::Analyze {
        Vec::new()
    } else {
        discovered_app_log_paths(&layout.discovered_app_logs)?
    };
    let files = expand_app_log_files(
        &candidates,
        resolved.safety.max_depth.min(MAX_APP_DISCOVERY_DEPTH),
    );
    logger.log(format!(
        "parser: {} application log file candidate(s)",
        files.len()
    ))?;

    let mut report = ParseReport::default();
    let mut events = Vec::new();
    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    for file in files {
        if let Ok(metadata) = fs::metadata(&file) {
            // .gz 按压缩后大小放行,解压侧由 LimitedReader 硬上限兜底
            if metadata.len() > max_bytes {
                report.errors.push(parse_error(
                    &file,
                    0,
                    "app_preflight",
                    format!(
                        "application log exceeds max-file-size limit: {} bytes",
                        metadata.len()
                    ),
                    &file.display().to_string(),
                    resolved.safety.redact,
                ));
                continue;
            }
        }
        // 单文件 IO 错误不再上抛中止整个解析阶段:降级为该文件的 ParseError 后继续
        parse_file(&file, resolved.safety.redact, max_bytes, &mut events, &mut report);
    }

    report.events = events.len();
    writers::write_app_events_jsonl(&layout.app_events, &events)?;
    Ok(report)
}

fn write_manual_candidates(path: &Path, candidates: &[PathBuf]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "path",
        "source",
        "framework",
        "priority",
        "exists",
        "notes",
        "evidence",
    ])?;
    for candidate in candidates {
        writer.write_record([
            candidate.display().to_string(),
            "manual".to_string(),
            infer_framework_from_path(candidate).unwrap_or_else(|| "unknown".to_string()),
            "10".to_string(),
            candidate.exists().to_string(),
            "explicit app-log-path".to_string(),
            candidate.display().to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn discovered_app_log_paths(path: &Path) -> Result<Vec<PathBuf>> {
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

fn expand_app_log_files(candidates: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
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
        if force_file || is_probable_app_log_file(path) {
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
        if child.is_dir() || is_probable_app_log_file(&child) {
            expand_one(&child, depth + 1, max_depth, seen, files, false);
        }
    }
}

fn is_probable_app_log_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".log")
        || name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.ends_with(".txt")
        || name.ends_with(".gz")
        || name.contains("application")
        || name.contains("laravel")
        || name.contains("pm2")
        || name.contains("stdout")
        || name.contains("stderr")
}

fn parse_file(
    path: &Path,
    redact: bool,
    max_bytes: u64,
    events: &mut Vec<AppLogEvent>,
    report: &mut ParseReport,
) {
    // 文件级 IO 错误(打开失败/损坏 gzip 流)降级为该文件的 ParseError,保证其余文件继续解析
    let mut reader = match super::compressed::open_log_reader(path, max_bytes) {
        Ok(reader) => reader,
        Err(error) => {
            report
                .errors
                .push(file_level_error(path, "app_log", format!("failed to open application log file: {error}")));
            return;
        }
    };
    let mut line_buffer = Vec::new();
    let mut line_number = 0_u64;

    loop {
        let line = match super::read_decoded_log_line(&mut *reader, &mut line_buffer) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                // 单行读取错误(含损坏 gzip 流)同样降级:记录后停止本文件,继续其余文件
                report.errors.push(file_level_error(
                    path,
                    "app_log",
                    format!("failed to read application log line, stream may be corrupt: {error}"),
                ));
                break;
            }
        };
        line_number += 1;
        // 剥离行首 UTF-8 BOM,避免格式识别错位
        let text = line.text.strip_prefix('\u{feff}').unwrap_or(&line.text);
        // 超长行:读取层已截断到 MAX_LINE_BYTES,记录 truncated 后仍尝试解析截断内容
        if line.was_truncated {
            let sample = safe_prefix(text, MAX_LINE_BYTES);
            report.errors.push(super::build_parse_error(
                path,
                line_number,
                "app_log",
                "line exceeded max line length and was truncated",
                sample,
                &line.raw_hash,
                redact,
            ));
        }
        if text.trim().is_empty() {
            continue;
        }
        report.lines_seen += 1;
        if line.had_invalid_utf8 {
            report.errors.push(super::build_parse_error(
                path,
                line_number,
                "app_log",
                "line contained invalid UTF-8 and was decoded lossily",
                text,
                &line.raw_hash,
                redact,
            ));
        }

        // 多行堆栈续行:无时间戳也无级别的行,若上一条事件属于同一文件,
        // 并入其 message(截断到 2000 字符),不再记 parse error。
        if extract_timestamp(text).is_none()
            && extract_level(text).is_none()
            && events
                .last()
                .is_some_and(|event| event.source_file == path.display().to_string())
        {
            if let Some(event) = events.last_mut() {
                let combined = match event.message_summary.as_deref() {
                    Some(message) => format!("{message}\n{}", text.trim()),
                    None => text.trim().to_string(),
                };
                event.message_summary = Some(combined.chars().take(2000).collect());
            }
            continue;
        }

        match parse_line(path, line_number, text) {
            Ok(mut event) => {
                if redact {
                    redact_event(&mut event);
                }
                events.push(event);
            }
            Err(message) => report.errors.push(super::build_parse_error(
                path,
                line_number,
                "app_log",
                message,
                text,
                &line.raw_hash,
                redact,
            )),
        }
    }
}

pub fn parse_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<AppLogEvent, String> {
    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        return parse_json_line(path, line_number, trimmed);
    }
    parse_text_line(path, line_number, trimmed)
}

fn parse_json_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<AppLogEvent, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "application JSON log is not an object".to_string())?;

    let timestamp = first_string(object, &["@timestamp", "timestamp", "time", "datetime"])
        .and_then(|value| parse_timestamp(&value).or(Some(value)));
    let message = first_string(object, &["message", "msg", "error", "detail"]);
    let exception_type = first_string(
        object,
        &["exception_type", "exception", "error_type", "error.kind"],
    )
    .or_else(|| message.as_deref().and_then(extract_exception_type));
    let framework = first_string(object, &["framework", "runtime", "service"])
        .or_else(|| infer_framework(path, line));

    Ok(AppLogEvent {
        timestamp,
        source_file: path.display().to_string(),
        line_number,
        framework,
        level: first_string(object, &["level", "severity", "loglevel"])
            .map(|value| value.to_ascii_lowercase()),
        logger: first_string(object, &["logger", "logger_name", "source"]),
        exception_type,
        message_summary: message.map(|value| summarize(&value)),
        request_id: first_string(object, &["request_id", "requestId", "req_id"]),
        trace_id: first_string(object, &["trace_id", "traceId", "trace"]),
        http_path: first_string(object, &["http_path", "path", "uri", "url", "request_path"]),
        user_summary: first_string(object, &["user", "user_id", "username", "principal"])
            .map(|value| summarize(&value)),
        raw_hash: super::access_log::sha256_hex(line.as_bytes()),
        parser_name: "app_json".to_string(),
        parse_confidence: if object.len() >= 4 { 0.86 } else { 0.72 },
    })
}

fn parse_text_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<AppLogEvent, String> {
    let timestamp = extract_timestamp(line);
    let level = extract_level(line);
    let exception_type = extract_exception_type(line);
    let framework = infer_framework(path, line);
    let http_path = extract_http_path(line);
    let trace_id = value_after_any(line, &["trace_id=", "traceId=", "trace-id=", "trace="]);
    let request_id = value_after_any(
        line,
        &["request_id=", "requestId=", "request-id=", "req_id="],
    );
    let logger = extract_logger(line, level.as_deref());

    if timestamp.is_none() && level.is_none() && exception_type.is_none() && http_path.is_none() {
        return Err("line does not look like a supported application log event".to_string());
    }

    Ok(AppLogEvent {
        timestamp,
        source_file: path.display().to_string(),
        line_number,
        framework,
        level,
        logger,
        exception_type,
        message_summary: Some(summarize(line)),
        request_id,
        trace_id,
        http_path,
        user_summary: value_after_any(line, &["user=", "user_id=", "username="]),
        raw_hash: super::access_log::sha256_hex(line.as_bytes()),
        parser_name: "app_text".to_string(),
        parse_confidence: 0.72,
    })
}

fn first_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = find_key_ignore_case(object, key).and_then(value_to_string) {
            return Some(value);
        }
    }
    None
}

fn find_key_ignore_case<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    object
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn extract_timestamp(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((candidate, _)) = rest.split_once(']') {
            return parse_timestamp(candidate);
        }
    }
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if first.contains('T') {
        return parse_timestamp(first.trim_end_matches(','));
    }
    let second = parts.next()?;
    parse_timestamp(&format!("{first} {}", second.trim_end_matches(',')))
}

fn parse_timestamp(value: &str) -> Option<String> {
    let normalized = normalize_timestamp(value);
    crate::time_utils::parse_datetime(&normalized)
        .ok()
        .map(crate::time_utils::format_iso)
}

fn normalize_timestamp(value: &str) -> String {
    let mut value = value
        .trim()
        .trim_matches('"')
        .trim_end_matches(',')
        .to_string();
    if let Some((prefix, suffix)) = value.split_once(',') {
        if suffix.chars().take_while(|ch| ch.is_ascii_digit()).count() >= 3 {
            value = prefix.to_string();
        }
    }
    if let Some(dot) = value.find('.') {
        let suffix = &value[dot + 1..];
        if suffix.chars().take_while(|ch| ch.is_ascii_digit()).count() >= 3 {
            let timezone = suffix
                .find(|ch: char| !ch.is_ascii_digit())
                .map(|index| &suffix[index..])
                .unwrap_or_default();
            value = format!("{}{}", &value[..dot], timezone);
        }
    }
    value
}

fn extract_level(line: &str) -> Option<String> {
    // 仅把"独立词元"识别为日志级别:词元前后只能是行首/行尾或非构词字符。
    // 紧邻的构词字符(字母/数字/下划线/斜杠/等号/@/#)会使词元失效,
    // 避免 SQLINFO、/INFO、level=INFO、user_INFO 这类嵌在标识符/路径/
    // 键值对里的级别词误判;括号/点号/冒号/空白包夹的级别词([INFO]、
    // production.ERROR:、ERROR: msg)仍正常识别。
    let is_level_token = |token: &str| {
        matches!(
            token.to_ascii_uppercase().as_str(),
            "TRACE" | "DEBUG" | "INFO" | "WARN" | "WARNING" | "ERROR" | "FATAL" | "CRITICAL"
        )
    };
    let wordish = |ch: char| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '/' | '=' | '@' | '#')
    };

    // 先切出字母数字词元(start, end)
    let mut tokens: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (index, ch) in line.char_indices() {
        if ch.is_ascii_alphanumeric() {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            tokens.push((begin, index));
        }
    }
    if let Some(begin) = start {
        tokens.push((begin, line.len()));
    }

    for (begin, end) in tokens {
        let token = &line[begin..end];
        if !is_level_token(token) {
            continue;
        }
        let before_ok = line[..begin]
            .chars()
            .next_back()
            .map_or(true, |ch| !wordish(ch));
        let after_ok = line[end..].chars().next().map_or(true, |ch| !wordish(ch));
        if before_ok && after_ok {
            return Some(token.to_ascii_lowercase());
        }
    }
    None
}

fn extract_exception_type(line: &str) -> Option<String> {
    let regex = regex::Regex::new(r"([A-Za-z_$][A-Za-z0-9_.$]*(?:Exception|Error|Throwable))")
        .expect("static exception regex is valid");
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|match_| match_.as_str().trim_matches('"').to_string())
}

fn extract_http_path(line: &str) -> Option<String> {
    for key in ["path=", "uri=", "url=", "http_path=", "request_path="] {
        if let Some(value) = value_after_any(line, &[key]) {
            if value.starts_with('/') {
                return Some(value);
            }
        }
    }
    let regex =
        regex::Regex::new(r"(?i)(?:Internal Server Error:|request(?:ed)? path:)\s*(/[^\s,;]+)")
            .expect("static path regex is valid");
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|match_| match_.as_str().trim_matches('"').to_string())
}

fn extract_logger(line: &str, level: Option<&str>) -> Option<String> {
    let level = level?;
    let marker = format!(" {} ", level.to_ascii_uppercase());
    let (_, tail) = line.split_once(&marker)?;
    tail.split_whitespace()
        .next()
        .filter(|value| value.contains('.') || value.contains("::"))
        .map(|value| value.trim_matches(':').to_string())
}

fn value_after_any(line: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(start) = find_case_insensitive(line, key) else {
            continue;
        };
        let value_start = start + key.len();
        let rest = line[value_start..].trim_start();
        let value = if let Some(stripped) = rest.strip_prefix('"') {
            stripped
                .split_once('"')
                .map(|(value, _)| value)
                .unwrap_or(stripped)
        } else {
            rest.split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | '}' | ']'))
                .next()
                .unwrap_or_default()
        };
        let value = value.trim_matches(['"', '\'', ':']);
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn infer_framework(path: &Path, line: &str) -> Option<String> {
    infer_framework_from_path(path).or_else(|| {
        let lower = line.to_ascii_lowercase();
        if lower.contains("spring") || lower.contains("org.springframework") {
            Some("spring".to_string())
        } else if lower.contains("django") {
            Some("django".to_string())
        } else if lower.contains("flask") || lower.contains("werkzeug") {
            Some("flask".to_string())
        } else if lower.contains("express") || lower.contains("node.js") || lower.contains("pm2") {
            Some("node".to_string())
        } else if lower.contains("laravel") || lower.contains("php") || lower.contains("php-fpm") {
            Some("php".to_string())
        } else if lower.contains("asp.net") || lower.contains("microsoft.aspnetcore") {
            Some("aspnet".to_string())
        } else {
            None
        }
    })
}

fn infer_framework_from_path(path: &Path) -> Option<String> {
    let name = path
        .display()
        .to_string()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if name.contains("spring") || name.contains("application.log") {
        Some("spring".to_string())
    } else if name.contains("django") || name.contains("gunicorn") || name.contains("uwsgi") {
        Some("django".to_string())
    } else if name.contains("flask") {
        Some("flask".to_string())
    } else if name.contains("node") || name.contains("express") || name.contains("pm2") {
        Some("node".to_string())
    } else if name.contains("laravel") || name.contains("php") {
        Some("php".to_string())
    } else if name.contains("aspnet") || name.contains("stdout") {
        Some("aspnet".to_string())
    } else {
        None
    }
}

fn summarize(value: &str) -> String {
    value.chars().take(300).collect()
}

fn redact_event(event: &mut AppLogEvent) {
    for field in [
        &mut event.logger,
        &mut event.exception_type,
        &mut event.message_summary,
        &mut event.request_id,
        &mut event.trace_id,
        &mut event.http_path,
        &mut event.user_summary,
    ]
    .into_iter()
    .flatten()
    {
        *field = crate::safety::redact_text(field);
    }
}

fn parse_error(
    path: &Path,
    line_number: u64,
    parser_name: &str,
    message: impl Into<String>,
    raw: &str,
    redact: bool,
) -> ParseError {
    ParseError {
        source_file: path.display().to_string(),
        line_number,
        parser_name: parser_name.to_string(),
        message: message.into(),
        raw_hash: super::access_log::sha256_hex(raw.as_bytes()),
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

/// 文件级错误记录:沿用"raw_hash 取文件路径哈希、raw_sample 置空"的既有约定。
fn file_level_error(path: &Path, parser_name: &str, message: String) -> ParseError {
    ParseError {
        source_file: path.display().to_string(),
        line_number: 0,
        parser_name: parser_name.to_string(),
        message,
        raw_hash: super::access_log::sha256_hex(path.display().to_string().as_bytes()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_application_log() {
        let event = parse_line(
            Path::new("application.log"),
            1,
            r#"{"timestamp":"2026-05-15T08:00:01Z","level":"ERROR","framework":"spring","exception_type":"java.sql.SQLSyntaxErrorException","message":"SQL syntax error near union","trace_id":"abc","path":"/product"}"#,
        )
        .unwrap();

        assert_eq!(event.framework.as_deref(), Some("spring"));
        assert_eq!(event.level.as_deref(), Some("error"));
        assert_eq!(event.http_path.as_deref(), Some("/product"));
        assert_eq!(
            event.exception_type.as_deref(),
            Some("java.sql.SQLSyntaxErrorException")
        );
    }

    #[test]
    fn parses_text_application_log() {
        let event = parse_line(
            Path::new("laravel.log"),
            2,
            r#"[2026-05-15 08:00:02] production.ERROR: SQLSTATE[42000] path=/login trace_id=def PDOException token=secret"#,
        )
        .unwrap();

        assert_eq!(event.framework.as_deref(), Some("php"));
        assert_eq!(event.level.as_deref(), Some("error"));
        assert_eq!(event.http_path.as_deref(), Some("/login"));
        assert_eq!(event.trace_id.as_deref(), Some("def"));
    }

    #[test]
    fn extract_level_requires_standalone_token() {
        // 嵌在标识符/路径/键值对里的级别词不再误判
        assert_eq!(extract_level("user_INFO_x uploaded a file"), None);
        assert_eq!(extract_level("GET /INFO HTTP/1.1 mapped"), None);
        assert_eq!(extract_level("set level=INFO in config"), None);
        assert_eq!(extract_level("downloaded INFORMATION.pdf"), None);
        // 独立词元(括号/点号/冒号/空白包夹)正常识别
        assert_eq!(extract_level("[ERROR] boom").as_deref(), Some("error"));
        assert_eq!(
            extract_level("[2026-05-15 08:00:02] production.ERROR: SQLSTATE").as_deref(),
            Some("error")
        );
        assert_eq!(extract_level("2026-05-15 08:00:02 INFO message").as_deref(), Some("info"));
        assert_eq!(extract_level("WARN, disk almost full").as_deref(), Some("warn"));
    }

    #[test]
    fn stack_continuation_lines_merge_into_previous_event() {
        // 多行堆栈:无时间戳且无级别的续行并入前一条事件 message,不记 parse error
        let root = crate::unique_test_dir("app-cont");
        fs::create_dir_all(&root).unwrap();
        let log = root.join("application.log");
        fs::write(
            &log,
            "2026-05-15 08:00:01 ERROR something failed\n\tat com.example.Foo.bar(Foo.java:42)\nCaused by: java.lang.NullPointerException: value missing\n\tat com.example.Baz.baz(Baz.java:7)\n",
        )
        .unwrap();

        let mut events = Vec::new();
        let mut report = ParseReport::default();
        parse_file(&log, false, u64::MAX, &mut events, &mut report);

        assert_eq!(events.len(), 1, "continuation lines must not create events");
        assert_eq!(report.errors.len(), 0, "{:?}", report.errors);
        let message = events[0].message_summary.as_deref().unwrap_or_default();
        assert!(message.contains("something failed"));
        assert!(message.contains("at com.example.Foo.bar"));
        assert!(message.contains("java.lang.NullPointerException"));

        fs::remove_dir_all(root).unwrap();
    }
}
