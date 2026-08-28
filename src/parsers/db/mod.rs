pub mod mssql;
pub mod mysql;
pub mod postgresql;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{DbLogEvent, DbType, ParseError};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

const MAX_DB_LOG_DISCOVERY_DEPTH: usize = 4;
const MAX_DB_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default)]
pub struct DbParseReport {
    pub events: usize,
    pub lines_seen: u64,
    pub errors: Vec<ParseError>,
}

#[derive(Debug, Clone)]
struct DbLogCandidate {
    path: PathBuf,
    db_type: DbType,
}

pub fn run_database_log_parsing(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<DbParseReport> {
    let candidates = db_log_candidates(resolved, layout)?;
    let files = expand_db_log_files(
        &candidates,
        resolved.safety.max_depth.min(MAX_DB_LOG_DISCOVERY_DEPTH),
    );
    logger.log(format!(
        "parser: {} database log file candidate(s)",
        files.len()
    ))?;

    let mut report = DbParseReport::default();
    let mut events = Vec::new();

    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    for candidate in files {
        if let Ok(metadata) = fs::metadata(&candidate.path) {
            // .gz 按压缩后大小放行,解压侧由 LimitedReader 硬上限兜底
            if metadata.len() > max_bytes {
                report.errors.push(ParseError {
                    source_file: candidate.path.display().to_string(),
                    line_number: 0,
                    parser_name: "db_preflight".to_string(),
                    message: format!(
                        "database log file exceeds max-file-size limit: {} bytes",
                        metadata.len()
                    ),
                    raw_hash: crate::parsers::access_log::sha256_hex(
                        candidate.path.display().to_string().as_bytes(),
                    ),
                    raw_sample: None,
                });
                continue;
            }
        }
        // 单文件 IO 错误不再上抛中止整个解析阶段:降级为该文件的 ParseError 后继续
        parse_db_file(
            &candidate,
            resolved.safety.redact,
            max_bytes,
            &mut events,
            &mut report,
        );
    }

    report.events = events.len();
    writers::write_db_events_jsonl(&layout.db_events, &events)?;
    Ok(report)
}

fn db_log_candidates(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<Vec<DbLogCandidate>> {
    if !resolved.db_log_paths.is_empty() {
        return Ok(resolved
            .db_log_paths
            .iter()
            .map(|path| DbLogCandidate {
                path: path.clone(),
                db_type: resolved.db_type,
            })
            .collect());
    }

    discovered_db_log_candidates(&layout.discovered_db_logs)
}

fn discovered_db_log_candidates(path: &Path) -> Result<Vec<DbLogCandidate>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut reader = csv::Reader::from_path(path)?;
    let headers = reader.headers()?.clone();
    let path_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("path"))
        .unwrap_or(0);
    let db_type_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("db_type"));
    let exists_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("exists"));

    let mut candidates = Vec::new();
    for row in reader.records().flatten() {
        let exists = exists_index
            .and_then(|index| row.get(index))
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        if !exists {
            continue;
        }
        let Some(value) = row.get(path_index) else {
            continue;
        };
        let db_type = db_type_index
            .and_then(|index| row.get(index))
            .and_then(|value| DbType::parse(value).ok())
            .unwrap_or(DbType::Auto);
        candidates.push(DbLogCandidate {
            path: PathBuf::from(value),
            db_type,
        });
    }
    Ok(candidates)
}

fn expand_db_log_files(candidates: &[DbLogCandidate], max_depth: usize) -> Vec<DbLogCandidate> {
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for candidate in candidates {
        expand_one(
            candidate,
            0,
            max_depth,
            &mut seen,
            &mut files,
            candidate.path.is_file(),
        );
    }
    files
}

fn expand_one(
    candidate: &DbLogCandidate,
    depth: usize,
    max_depth: usize,
    seen: &mut HashSet<String>,
    files: &mut Vec<DbLogCandidate>,
    force_file: bool,
) {
    // 仅 Windows 路径不区分大小写才做 lowercase;Linux 大小写敏感路径误合并会丢文件
    let display = candidate
        .path
        .display()
        .to_string()
        .replace('\\', "/");
    let key = if cfg!(windows) {
        display.to_ascii_lowercase()
    } else {
        display
    };
    if !seen.insert(key) {
        return;
    }

    if candidate.path.is_file() {
        if force_file || is_probable_db_log_file(&candidate.path) {
            files.push(candidate.clone());
        }
        return;
    }
    if !candidate.path.is_dir() || depth >= max_depth {
        return;
    }

    let Ok(entries) = fs::read_dir(&candidate.path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() || is_probable_db_log_file(&child) {
            expand_one(
                &DbLogCandidate {
                    path: child,
                    db_type: candidate.db_type,
                },
                depth + 1,
                max_depth,
                seen,
                files,
                false,
            );
        }
    }
}

fn is_probable_db_log_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".log")
        || name.ends_with(".err")
        || name.ends_with(".csv")
        || name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.ends_with(".gz")
        || name == "errorlog"
        || name.starts_with("postgresql-")
        || name.starts_with("mysql")
        || name.starts_with("mariadb")
        || name.starts_with("slow")
}

fn parse_db_file(
    candidate: &DbLogCandidate,
    redact: bool,
    max_bytes: u64,
    events: &mut Vec<DbLogEvent>,
    report: &mut DbParseReport,
) {
    // 文件级 IO 错误(打开失败/损坏 gzip 流)降级为该文件的 ParseError,保证其余文件继续解析
    let mut reader = match crate::parsers::compressed::open_log_reader(&candidate.path, max_bytes) {
        Ok(reader) => reader,
        Err(error) => {
            report.errors.push(file_level_error(
                &candidate.path,
                "db_log",
                format!("failed to open database log file: {error}"),
            ));
            return;
        }
    };
    let mut line_buffer = Vec::new();
    let mut line_number = 0_u64;

    loop {
        let line = match crate::parsers::read_decoded_log_line(&mut *reader, &mut line_buffer) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                // 单行读取错误(含损坏 gzip 流)同样降级:记录后停止本文件,继续其余文件
                report.errors.push(file_level_error(
                    &candidate.path,
                    "db_log",
                    format!("failed to read database log line, stream may be corrupt: {error}"),
                ));
                break;
            }
        };
        line_number += 1;
        // 剥离行首 UTF-8 BOM,避免时间戳/格式识别错位
        let text = line.text.strip_prefix('\u{feff}').unwrap_or(&line.text);
        // 超长行:读取层已截断到 MAX_DB_LINE_BYTES,记录 truncated 后仍尝试解析截断内容
        if line.was_truncated {
            let sample = safe_prefix(text, MAX_DB_LINE_BYTES);
            report.errors.push(crate::parsers::build_parse_error(
                &candidate.path,
                line_number,
                "db_log",
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
            report.errors.push(crate::parsers::build_parse_error(
                &candidate.path,
                line_number,
                "db_log",
                "line contained invalid UTF-8 and was decoded lossily",
                text,
                &line.raw_hash,
                redact,
            ));
        }

        match parse_db_line(&candidate.path, line_number, text, candidate.db_type) {
            Ok(mut event) => {
                if redact {
                    redact_db_event(&mut event);
                }
                events.push(event);
            }
            Err(message) => report.errors.push(crate::parsers::build_parse_error(
                &candidate.path,
                line_number,
                "db_log",
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
        raw_hash: crate::parsers::access_log::sha256_hex(path.display().to_string().as_bytes()),
        raw_sample: None,
    }
}

fn parse_db_line(
    path: &Path,
    line_number: u64,
    line: &str,
    selected: DbType,
) -> std::result::Result<DbLogEvent, String> {
    match effective_db_type(path, line, selected) {
        DbType::MySql | DbType::MariaDb => mysql::parse_line(path, line_number, line),
        DbType::PostgreSql => postgresql::parse_line(path, line_number, line),
        DbType::Mssql => mssql::parse_line(path, line_number, line),
        DbType::Auto => mysql::parse_line(path, line_number, line)
            .or_else(|_| postgresql::parse_line(path, line_number, line))
            .or_else(|_| mssql::parse_line(path, line_number, line)),
    }
}

fn effective_db_type(path: &Path, line: &str, selected: DbType) -> DbType {
    if selected != DbType::Auto {
        return selected;
    }
    let path_text = path.display().to_string().to_ascii_lowercase();
    let line_text = line.to_ascii_lowercase();
    if path_text.contains("postgres") || line_text.contains("pgaudit") {
        DbType::PostgreSql
    } else if path_text.contains("mssql")
        || path_text.contains("sql server")
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .eq_ignore_ascii_case("ERRORLOG")
    {
        DbType::Mssql
    } else if path_text.contains("mariadb") {
        DbType::MariaDb
    } else if path_text.contains("mysql") || line_text.contains("mysqld") {
        DbType::MySql
    } else {
        DbType::Auto
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

fn redact_db_event(event: &mut DbLogEvent) {
    for field in [
        &mut event.db_user,
        &mut event.db_name,
        &mut event.statement_summary,
        &mut event.error_code,
    ]
    .into_iter()
    .flatten()
    {
        *field = crate::safety::redact_text(field);
    }
}

pub(crate) fn build_event(
    path: &Path,
    line_number: u64,
    line: &str,
    db_type: DbType,
    parsed: ParsedDbLine,
    parser_confidence: f32,
) -> DbLogEvent {
    DbLogEvent {
        timestamp: parsed.timestamp,
        source_file: path.display().to_string(),
        line_number,
        db_type: db_type.as_str().to_string(),
        db_instance: parsed.db_instance,
        db_user: parsed.db_user,
        db_name: parsed.db_name,
        client_ip: parsed.client_ip,
        client_port: parsed.client_port,
        session_id: parsed.session_id,
        statement_type: parsed.statement_type,
        statement_summary: parsed.statement_summary,
        duration_ms: parsed.duration_ms,
        rows: parsed.rows,
        error_code: parsed.error_code,
        severity: parsed.severity,
        raw_hash: crate::parsers::access_log::sha256_hex(line.as_bytes()),
        parser_confidence,
    }
}

#[derive(Debug, Default)]
pub(crate) struct ParsedDbLine {
    pub timestamp: Option<String>,
    pub db_instance: Option<String>,
    pub db_user: Option<String>,
    pub db_name: Option<String>,
    pub client_ip: Option<String>,
    pub client_port: Option<u16>,
    pub session_id: Option<String>,
    pub statement_type: Option<String>,
    pub statement_summary: Option<String>,
    pub duration_ms: Option<f64>,
    pub rows: Option<u64>,
    pub error_code: Option<String>,
    pub severity: Option<String>,
}

pub(crate) fn parse_leading_timestamp(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim_start();
    if let Some(token) = trimmed.split_whitespace().next() {
        if token.contains('T') {
            let token = token.trim_end_matches(',');
            if let Ok(parsed) = crate::time_utils::parse_datetime(token) {
                let rest = trimmed[token.len()..].trim_start();
                return Some((crate::time_utils::format_iso(parsed), rest));
            }
        }
    }

    if trimmed.len() >= 19 {
        // 字节 19 可能落在多字节字符中间(中文 MySQL 错误日志实测触发),
        // 必须先回退到最近的字符边界再切片,否则字节切片直接 panic。
        let mut end = 19;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        let prefix = &trimmed[..end];
        if let Ok(parsed) = crate::time_utils::parse_datetime(prefix) {
            let rest = trimmed[end..].trim_start_matches(|ch: char| {
                ch.is_ascii_whitespace() || ch == '.' || ch.is_ascii_digit()
            });
            return Some((crate::time_utils::format_iso(parsed), rest.trim_start()));
        }
    }

    None
}

pub(crate) fn classify_statement(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("access denied")
        || lower.contains("login failed")
        || lower.contains("password authentication failed")
        || lower.contains("error: 18456")
    {
        "auth_failure"
    } else if lower.contains("load_file")
        || lower.contains("pg_read_file")
        || lower.contains("pg_ls_dir")
    {
        "file_read"
    } else if lower.contains("into outfile") || lower.contains("into dumpfile") {
        "file_write"
    } else if lower.contains("sleep(")
        || lower.contains("benchmark(")
        || lower.contains("pg_sleep")
        || lower.contains("waitfor delay")
    {
        "delay"
    } else if lower.contains("create function")
        || lower.contains("install plugin")
        || (lower.contains("copy") && lower.contains("program"))
        || lower.contains("xp_cmdshell")
        || lower.contains("sp_oacreate")
        || lower.contains("sp_configure")
        || lower.contains("create extension")
    {
        "code_execution"
    } else if lower.contains("grant ")
        || lower.contains("create user")
        || lower.contains("alter user")
        || lower.contains("set password")
        || lower.contains("create role")
        || lower.contains("alter role")
        || lower.contains("create login")
        || lower.contains("alter login")
        || lower.contains("sp_addsrvrolemember")
    {
        "privilege_change"
    } else if lower.contains("information_schema") || lower.contains("mysql.user") {
        "enumeration"
    } else if lower.contains("openquery") || lower.contains("opendatasource") {
        "linked_server"
    } else if lower.contains("statement:")
        || lower.contains(" query ")
        || lower.starts_with("select ")
        || lower.starts_with("insert ")
        || lower.starts_with("update ")
        || lower.starts_with("delete ")
    {
        "query"
    } else {
        "other"
    }
    .to_string()
}

pub(crate) fn summarize_statement(value: &str) -> Option<String> {
    let trimmed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() {
        return None;
    }
    let without_literals = redact_sql_literals(&trimmed);
    Some(
        without_literals
            .chars()
            .take(240)
            .collect::<String>()
            .trim()
            .to_string(),
    )
}

fn redact_sql_literals(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            output.push('\'');
            output.push('?');
            output.push('\'');
            for next in chars.by_ref() {
                if next == '\'' {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    output
}

pub(crate) fn first_ipv4(text: &str) -> Option<String> {
    // 逐候选校验八位组 0-255:版本号(如 5.7.30.11)之类的点分数字串不能误当 IP,
    // 首个候选不合法时继续向后找真正的 IPv4。
    regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        .ok()?
        .find_iter(text)
        .map(|matched| matched.as_str())
        .find(|candidate| candidate.split('.').all(|octet| octet.parse::<u8>().is_ok()))
        .map(str::to_string)
}

pub(crate) fn single_quoted_after(text: &str, marker: &str) -> Option<String> {
    let start = text
        .to_ascii_lowercase()
        .find(&marker.to_ascii_lowercase())?
        + marker.len();
    let rest = &text[start..];
    let quote = rest.find('\'')? + 1;
    let after = &rest[quote..];
    let end = after.find('\'')?;
    Some(after[..end].to_string())
}

pub(crate) fn double_quoted_after(text: &str, marker: &str) -> Option<String> {
    let start = text
        .to_ascii_lowercase()
        .find(&marker.to_ascii_lowercase())?
        + marker.len();
    let rest = &text[start..];
    let quote = rest.find('"')? + 1;
    let after = &rest[quote..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_timestamp_survives_multibyte_prefix() {
        // 中文 MySQL 错误日志:第 19 字节落在多字节字符中间,字节切片不得 panic
        let line = "数据库错误日志中文内容测试文本";
        assert!(line.len() >= 19);
        assert!(!line.is_char_boundary(19));
        assert!(parse_leading_timestamp(line).is_none());

        // 正常带中文尾部的错误行仍能解析时间戳
        let (timestamp, rest) = parse_leading_timestamp("2026-05-15 08:00:01 中文错误内容")
            .expect("timestamp parses");
        assert!(timestamp.starts_with("2026-05-15T08:00:01"));
        assert!(rest.contains("中文错误内容"));
    }

    #[test]
    fn mysql_line_with_chinese_text_does_not_panic() {
        // 中文行整体走 MySQL 解析(缺时间戳 → Err 而非 panic)
        let result = mysql::parse_line(Path::new("mysql.err"), 1, "错误错误错误错误错误错误错误错误");
        assert!(result.is_err());
    }

    #[test]
    fn first_ipv4_validates_octets() {
        // 八位组非法(>255)的点分数字串(如版本号 5.7.442.11)不能当 IP;
        // 应跳过并继续向后找到真正的合法 IPv4。
        let text = "running 5.7.442.11 build, connect from 192.168.1.44";
        assert_eq!(first_ipv4(text).as_deref(), Some("192.168.1.44"));
        // 全部候选都非法时返回 None
        assert_eq!(first_ipv4("upgrade 999.999.999.999 done"), None);
        assert_eq!(first_ipv4("no ip here"), None);
        assert_eq!(first_ipv4("connect from 10.0.0.5 ok").as_deref(), Some("10.0.0.5"));
    }
}
