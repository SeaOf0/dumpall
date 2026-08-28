use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{ParseError, RunMode, WafLogEvent};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use super::ParseReport;

const MAX_WAF_DISCOVERY_DEPTH: usize = 4;
const MAX_LINE_BYTES: usize = 1024 * 1024;

pub fn run_waf_log_parsing(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<ParseReport> {
    if !resolved.waf_log_paths.is_empty() {
        write_manual_candidates(&layout.discovered_waf_logs, &resolved.waf_log_paths)?;
    }

    let candidates = if !resolved.waf_log_paths.is_empty() {
        resolved.waf_log_paths.clone()
    } else if resolved.mode == RunMode::Analyze {
        Vec::new()
    } else {
        discovered_waf_log_paths(&layout.discovered_waf_logs)?
    };
    let files = expand_waf_log_files(
        &candidates,
        resolved.safety.max_depth.min(MAX_WAF_DISCOVERY_DEPTH),
    );
    logger.log(format!(
        "parser: {} WAF/CDN log file candidate(s)",
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
                    "waf_preflight",
                    format!(
                        "WAF log exceeds max-file-size limit: {} bytes",
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
    writers::write_waf_events_jsonl(&layout.waf_events, &events)?;
    Ok(report)
}

fn write_manual_candidates(path: &Path, candidates: &[PathBuf]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "path", "source", "vendor", "priority", "exists", "notes", "evidence",
    ])?;
    for candidate in candidates {
        writer.write_record([
            candidate.display().to_string(),
            "manual".to_string(),
            infer_vendor_from_path(candidate).unwrap_or_else(|| "unknown".to_string()),
            "10".to_string(),
            candidate.exists().to_string(),
            "explicit waf-log-path".to_string(),
            candidate.display().to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn discovered_waf_log_paths(path: &Path) -> Result<Vec<PathBuf>> {
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

fn expand_waf_log_files(candidates: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
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
        if force_file || is_probable_waf_log_file(path) {
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
        if child.is_dir() || is_probable_waf_log_file(&child) {
            expand_one(&child, depth + 1, max_depth, seen, files, false);
        }
    }
}

fn is_probable_waf_log_file(path: &Path) -> bool {
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
        || name.contains("waf")
        || name.contains("modsec")
        || name.contains("cloudflare")
        || name.contains("cdn")
}

fn parse_file(
    path: &Path,
    redact: bool,
    max_bytes: u64,
    events: &mut Vec<WafLogEvent>,
    report: &mut ParseReport,
) {
    // 文件级 IO 错误(打开失败/损坏 gzip 流)降级为该文件的 ParseError,保证其余文件继续解析
    let mut reader = match super::compressed::open_log_reader(path, max_bytes) {
        Ok(reader) => reader,
        Err(error) => {
            report
                .errors
                .push(file_level_error(path, "waf_log", format!("failed to open WAF log file: {error}")));
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
                    "waf_log",
                    format!("failed to read WAF log line, stream may be corrupt: {error}"),
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
                "waf_log",
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
                "waf_log",
                "line contained invalid UTF-8 and was decoded lossily",
                text,
                &line.raw_hash,
                redact,
            ));
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
                "waf_log",
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
) -> std::result::Result<WafLogEvent, String> {
    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        return parse_json_line(path, line_number, trimmed);
    }
    if trimmed.to_ascii_lowercase().contains("modsecurity") {
        return parse_modsecurity_line(path, line_number, trimmed);
    }
    parse_key_value_line(path, line_number, trimmed)
}

fn parse_json_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<WafLogEvent, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "WAF JSON log is not an object".to_string())?;
    let timestamp = first_string(object, &["@timestamp", "timestamp", "time", "datetime"])
        .and_then(|value| parse_timestamp(&value).or(Some(value)));
    let vendor = first_string(object, &["vendor", "source", "service", "provider"])
        .or_else(|| infer_vendor_from_path(path));

    Ok(WafLogEvent {
        timestamp,
        source_file: path.display().to_string(),
        line_number,
        vendor,
        action: first_string(
            object,
            &["action", "waf_action", "disposition", "event_action"],
        )
        .map(normalize_action),
        rule_id: first_string(
            object,
            &["rule_id", "ruleId", "rule", "signature_id", "RuleID"],
        ),
        rule_name: first_string(
            object,
            &[
                "rule_name",
                "ruleName",
                "message",
                "signature",
                "description",
            ],
        ),
        client_ip: first_string(
            object,
            &[
                "client_ip",
                "source_ip",
                "src_ip",
                "remote_ip",
                "ClientIP",
                "CF-Connecting-IP",
                "True-Client-IP",
            ],
        ),
        proxy_ip: first_string(object, &["proxy_ip", "edge_ip", "remote_addr", "server_ip"]),
        host: first_string(object, &["host", "hostname", "http_host"]),
        method: first_string(object, &["method", "http_method"]),
        path: first_string(object, &["path", "uri_path", "uri", "request_uri"]),
        status: first_string(object, &["status", "sc_status", "EdgeResponseStatus"])
            .and_then(|value| value.parse::<u16>().ok()),
        score: first_string(object, &["score", "risk_score", "anomaly_score"])
            .and_then(|value| value.parse::<f64>().ok()),
        raw_hash: super::access_log::sha256_hex(line.as_bytes()),
        parser_name: "waf_json".to_string(),
        parse_confidence: if object.len() >= 5 { 0.88 } else { 0.74 },
    })
}

fn parse_modsecurity_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<WafLogEvent, String> {
    let lower = line.to_ascii_lowercase();
    let action = if lower.contains("access denied") || lower.contains("blocked") {
        Some("block".to_string())
    } else if lower.contains("warning") {
        Some("log".to_string())
    } else {
        None
    };

    Ok(WafLogEvent {
        timestamp: extract_timestamp(line),
        source_file: path.display().to_string(),
        line_number,
        vendor: Some("modsecurity".to_string()),
        action,
        rule_id: bracket_value(line, "id"),
        rule_name: bracket_value(line, "msg"),
        client_ip: bracket_value(line, "client"),
        proxy_ip: None,
        host: bracket_value(line, "hostname"),
        method: None,
        path: bracket_value(line, "uri"),
        status: bracket_value(line, "status").and_then(|value| value.parse::<u16>().ok()),
        score: None,
        raw_hash: super::access_log::sha256_hex(line.as_bytes()),
        parser_name: "modsecurity".to_string(),
        parse_confidence: 0.82,
    })
}

fn parse_key_value_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<WafLogEvent, String> {
    let fields = parse_key_values(line);
    if fields.is_empty() {
        return Err("line does not look like a supported WAF log event".to_string());
    }

    Ok(WafLogEvent {
        timestamp: fields
            .get("timestamp")
            .or_else(|| fields.get("time"))
            .and_then(|value| parse_timestamp(value))
            .or_else(|| extract_timestamp(line)),
        source_file: path.display().to_string(),
        line_number,
        vendor: fields
            .get("vendor")
            .or_else(|| fields.get("source"))
            .cloned()
            .or_else(|| infer_vendor_from_path(path)),
        action: fields.get("action").cloned().map(normalize_action),
        rule_id: fields
            .get("rule_id")
            .or_else(|| fields.get("rule"))
            .cloned(),
        rule_name: fields
            .get("rule_name")
            .or_else(|| fields.get("message"))
            .cloned(),
        client_ip: fields
            .get("client_ip")
            .or_else(|| fields.get("source_ip"))
            .or_else(|| fields.get("src_ip"))
            .cloned(),
        proxy_ip: fields
            .get("proxy_ip")
            .or_else(|| fields.get("remote_addr"))
            .cloned(),
        host: fields
            .get("host")
            .or_else(|| fields.get("hostname"))
            .cloned(),
        method: fields.get("method").cloned(),
        path: fields
            .get("path")
            .or_else(|| fields.get("uri"))
            .or_else(|| fields.get("request_uri"))
            .cloned(),
        status: fields
            .get("status")
            .and_then(|value| value.parse::<u16>().ok()),
        score: fields
            .get("score")
            .and_then(|value| value.parse::<f64>().ok()),
        raw_hash: super::access_log::sha256_hex(line.as_bytes()),
        parser_name: "waf_kv".to_string(),
        parse_confidence: 0.76,
    })
}

fn parse_key_values(line: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let mut cursor = 0;
    let bytes = line.as_bytes();
    while cursor < line.len() {
        while cursor < line.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let key_start = cursor;
        while cursor < line.len() && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'=' {
            cursor += 1;
        }
        if cursor >= line.len() || bytes[cursor] != b'=' {
            cursor += 1;
            continue;
        }
        let key = line[key_start..cursor]
            .trim()
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .replace(['-', '.'], "_");
        cursor += 1;
        let value = if cursor < line.len() && matches!(bytes[cursor], b'"' | b'\'') {
            let quote = bytes[cursor];
            cursor += 1;
            let value_start = cursor;
            while cursor < line.len() && bytes[cursor] != quote {
                cursor += 1;
            }
            let value = line[value_start..cursor].to_string();
            cursor = cursor.saturating_add(1);
            value
        } else {
            let value_start = cursor;
            while cursor < line.len() && !bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            line[value_start..cursor].to_string()
        };
        if !key.is_empty() && !value.is_empty() {
            fields.insert(key, value);
        }
    }
    fields
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
    let value = value.trim().trim_matches(['"', '\'']);
    crate::time_utils::parse_datetime(value)
        .ok()
        .map(crate::time_utils::format_iso)
}

fn normalize_action(value: String) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.contains("block") || lower.contains("deny") || lower.contains("drop") {
        "block".to_string()
    } else if lower.contains("challenge") || lower.contains("captcha") {
        "challenge".to_string()
    } else if lower.contains("allow") || lower.contains("pass") {
        "allow".to_string()
    } else {
        lower
    }
}

fn bracket_value(line: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"[{key} ""#);
    let start = line.find(&pattern)? + pattern.len();
    let end = line[start..].find(r#""]"#)? + start;
    Some(line[start..end].to_string())
}

fn infer_vendor_from_path(path: &Path) -> Option<String> {
    let name = path
        .display()
        .to_string()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if name.contains("modsec") || name.contains("modsecurity") {
        Some("modsecurity".to_string())
    } else if name.contains("cloudflare") {
        Some("cloudflare".to_string())
    } else if name.contains("akamai") {
        Some("akamai".to_string())
    } else if name.contains("aws") || name.contains("alb") {
        Some("aws".to_string())
    } else if name.contains("waf") {
        Some("waf".to_string())
    } else {
        None
    }
}

fn redact_event(event: &mut WafLogEvent) {
    for field in [
        &mut event.vendor,
        &mut event.action,
        &mut event.rule_id,
        &mut event.rule_name,
        &mut event.client_ip,
        &mut event.proxy_ip,
        &mut event.host,
        &mut event.method,
        &mut event.path,
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
    fn parses_json_waf_log() {
        let event = parse_line(
            Path::new("cloudflare-waf.jsonl"),
            1,
            r#"{"timestamp":"2026-05-15T08:00:01Z","vendor":"cloudflare","action":"block","rule_id":"100173","rule_name":"SQLi","client_ip":"203.0.113.9","proxy_ip":"10.0.0.5","host":"example.test","method":"GET","path":"/product","status":403,"score":90}"#,
        )
        .unwrap();

        assert_eq!(event.vendor.as_deref(), Some("cloudflare"));
        assert_eq!(event.action.as_deref(), Some("block"));
        assert_eq!(event.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(event.path.as_deref(), Some("/product"));
    }

    #[test]
    fn parses_modsecurity_line() {
        let event = parse_line(
            Path::new("modsec_audit.log"),
            2,
            r#"[2026-05-15T08:00:02Z] ModSecurity: Warning. [id "942100"] [msg "SQL Injection Attack Detected"] [hostname "example.test"] [uri "/login"] [client "198.51.100.8"] [status "403"]"#,
        )
        .unwrap();

        assert_eq!(event.vendor.as_deref(), Some("modsecurity"));
        assert_eq!(event.rule_id.as_deref(), Some("942100"));
        assert_eq!(event.action.as_deref(), Some("log"));
        assert_eq!(event.status, Some(403));
    }
}
