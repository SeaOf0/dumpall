use std::path::Path;

use crate::model::{DbLogEvent, DbType};

use super::{
    build_event, classify_statement, first_ipv4, parse_leading_timestamp, single_quoted_after,
    summarize_statement, ParsedDbLine,
};

pub fn parse_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<DbLogEvent, String> {
    let (timestamp, rest) =
        parse_leading_timestamp(line).ok_or_else(|| "missing database timestamp".to_string())?;
    let mut parsed = ParsedDbLine {
        timestamp: Some(timestamp),
        ..ParsedDbLine::default()
    };

    let message = strip_spid(rest);
    let lower = message.to_ascii_lowercase();
    if lower.contains("login failed") || lower.contains("error: 18456") {
        parsed.statement_type = Some("auth_failure".to_string());
        parsed.db_user = single_quoted_after(message, "user ");
        parsed.client_ip = extract_client_ip(message).or_else(|| first_ipv4(message));
        parsed.error_code = Some("18456".to_string());
        parsed.severity = Some("error".to_string());
    }

    if parsed.statement_type.is_none() {
        parsed.statement_type = Some(classify_statement(message));
    }
    if parsed.client_ip.is_none() {
        parsed.client_ip = extract_client_ip(message).or_else(|| first_ipv4(message));
    }
    parsed.statement_summary = summarize_statement(message);

    Ok(build_event(
        path,
        line_number,
        line,
        DbType::Mssql,
        parsed,
        0.8,
    ))
}

fn strip_spid(value: &str) -> &str {
    let trimmed = value.trim_start();
    let Some((first, rest)) = trimmed.split_once(char::is_whitespace) else {
        return trimmed;
    };
    if first.to_ascii_lowercase().starts_with("spid") {
        rest.trim_start()
    } else {
        trimmed
    }
}

fn extract_client_ip(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let marker = "[client:";
    let start = lower.find(marker)? + marker.len();
    let rest = &value[start..];
    let end = rest.find(']')?;
    Some(rest[..end].trim().to_string())
}
