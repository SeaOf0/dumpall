use std::path::Path;

use serde_json::Value;

use crate::model::{DbLogEvent, DbType};

use super::{
    build_event, classify_statement, double_quoted_after, first_ipv4, parse_leading_timestamp,
    summarize_statement, ParsedDbLine,
};

pub fn parse_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<DbLogEvent, String> {
    if line.trim_start().starts_with('{') {
        return parse_json_line(path, line_number, line);
    }

    let (timestamp, rest) =
        parse_leading_timestamp(line).ok_or_else(|| "missing database timestamp".to_string())?;
    let rest = rest.trim_start_matches("UTC").trim_start();
    let mut parsed = ParsedDbLine {
        timestamp: Some(timestamp),
        ..ParsedDbLine::default()
    };

    let message = parse_prefix(rest, &mut parsed);
    if message
        .to_ascii_lowercase()
        .contains("password authentication failed")
    {
        parsed.statement_type = Some("auth_failure".to_string());
        parsed.db_user = parsed
            .db_user
            .or_else(|| double_quoted_after(message, "user "));
        parsed.client_ip = parsed.client_ip.or_else(|| first_ipv4(message));
        parsed.severity = Some("fatal".to_string());
    }

    let statement = message
        .split_once("statement:")
        .map(|(_, statement)| statement.trim())
        .unwrap_or(message);
    if parsed.statement_type.is_none() {
        parsed.statement_type = Some(classify_statement(statement));
    }
    if parsed.client_ip.is_none() {
        parsed.client_ip = first_ipv4(message);
    }
    parsed.statement_summary = summarize_statement(statement);

    Ok(build_event(
        path,
        line_number,
        line,
        DbType::PostgreSql,
        parsed,
        0.8,
    ))
}

fn parse_json_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<DbLogEvent, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let timestamp = value
        .get("timestamp")
        .or_else(|| value.get("time"))
        .and_then(Value::as_str)
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
        .map(crate::time_utils::format_iso);
    let statement = value
        .get("statement")
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if timestamp.is_none() && statement.is_empty() {
        return Err("JSON PostgreSQL log missing timestamp and statement".to_string());
    }

    let parsed = ParsedDbLine {
        timestamp,
        db_user: value
            .get("user")
            .or_else(|| value.get("username"))
            .and_then(Value::as_str)
            .map(str::to_string),
        db_name: value
            .get("database")
            .or_else(|| value.get("db"))
            .and_then(Value::as_str)
            .map(str::to_string),
        client_ip: value
            .get("client_ip")
            .or_else(|| value.get("remote_host"))
            .and_then(Value::as_str)
            .map(str::to_string),
        session_id: value
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        statement_type: Some(classify_statement(statement)),
        statement_summary: summarize_statement(statement),
        duration_ms: value.get("duration_ms").and_then(Value::as_f64),
        rows: value.get("rows").and_then(Value::as_u64),
        severity: value
            .get("level")
            .or_else(|| value.get("severity"))
            .and_then(Value::as_str)
            .map(str::to_string),
        ..ParsedDbLine::default()
    };

    Ok(build_event(
        path,
        line_number,
        line,
        DbType::PostgreSql,
        parsed,
        0.86,
    ))
}

fn parse_prefix<'a>(value: &'a str, parsed: &mut ParsedDbLine) -> &'a str {
    let mut rest = value.trim_start();
    if let Some(end) = rest.find(']') {
        if rest.starts_with('[') {
            parsed.session_id = Some(rest[1..end].to_string());
            rest = rest[end + 1..].trim_start();
        }
    }

    let mut tokens = rest.split_whitespace();
    let first = tokens.next().unwrap_or_default();
    let second = tokens.next().unwrap_or_default();
    if let Some((user, db)) = first.split_once('@') {
        parsed.db_user = Some(user.to_string());
        parsed.db_name = Some(db.to_string());
        if looks_like_ip(second) {
            parsed.client_ip = Some(second.to_string());
        }
        // 不按"单空白字节"假设做字节算术:双空格/全角空格(多字节空白)会让
        // rest[consumed..] 切进字符中间 panic,改为按 token 边界定位后重建。
        let token_count = if second.is_empty() { 1 } else { 2 };
        let boundary = offset_after_tokens(rest, token_count);
        rest = rest[boundary..].trim_start();
    }

    if let Some((level, after)) = rest.split_once(':') {
        let level = level.split_whitespace().last().unwrap_or(level).trim();
        if !level.is_empty() && level.len() <= 12 {
            parsed.severity = Some(level.to_ascii_lowercase());
            return after.trim_start();
        }
    }

    rest
}

/// 返回跳过前 `count` 个空白分隔 token 之后的字节偏移(始终落在字符边界上)。
/// 空白判定与 split_whitespace 一致(含全角空格等多字节空白)。
fn offset_after_tokens(value: &str, count: usize) -> usize {
    let mut seen = 0_usize;
    let mut in_token = false;
    for (index, ch) in value.char_indices() {
        if ch.is_whitespace() {
            if in_token {
                seen += 1;
                in_token = false;
                if seen >= count {
                    return index;
                }
            }
        } else {
            in_token = true;
        }
    }
    value.len()
}

fn looks_like_ip(value: &str) -> bool {
    value.chars().filter(|ch| *ch == '.').count() == 3
        && value.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_whitespace_prefix_does_not_panic() {
        // 用户@库 与后续 token 之间是多字节全角空格:旧的"单空白字节"字节算术
        // 会把 rest[consumed..] 切进字符中间 panic,现在按 token 边界重建。
        let line = "2026-05-15 08:00:00 UTC postgres@mydb\u{3000}\u{3000}\u{3000}\u{3000}x LOG:  statement: select 1";
        let event = parse_line(Path::new("postgresql.log"), 1, line)
            .expect("line parses despite multibyte whitespace");
        assert_eq!(event.db_user.as_deref(), Some("postgres"));
        assert_eq!(event.db_name.as_deref(), Some("mydb"));
        assert!(event
            .statement_summary
            .as_deref()
            .unwrap_or_default()
            .contains("select 1"));
    }

    #[test]
    fn double_space_prefix_still_parses() {
        // 双空格(旧实现会算错剩余起点,导致 severity/语句错位)
        let line = "2026-05-15 08:00:00 UTC postgres@mydb 127.0.0.1 LOG:  statement: select 2";
        let event = parse_line(Path::new("postgresql.log"), 1, line).unwrap();
        assert_eq!(event.client_ip.as_deref(), Some("127.0.0.1"));
        assert!(event
            .statement_summary
            .as_deref()
            .unwrap_or_default()
            .contains("select 2"));
    }
}
