use std::path::Path;

use serde_json::Value;

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
    if line.trim_start().starts_with('{') {
        return parse_json_line(path, line_number, line);
    }

    let (timestamp, rest) =
        parse_leading_timestamp(line).ok_or_else(|| "missing database timestamp".to_string())?;
    let mut parsed = ParsedDbLine {
        timestamp: Some(timestamp),
        ..ParsedDbLine::default()
    };

    let mut message = rest.trim();
    if let Some((session, after_session)) = take_session_id(message) {
        parsed.session_id = Some(session.to_string());
        message = after_session.trim_start();
    }
    if let Some((command, after_command)) = take_command(message) {
        parsed.statement_type = Some(command_to_statement_type(command, after_command));
        message = after_command.trim_start();
    }

    if message.to_ascii_lowercase().contains("access denied") {
        parsed.statement_type = Some("auth_failure".to_string());
        parsed.db_user = single_quoted_after(message, "user ");
        parsed.client_ip = first_ipv4(message);
        parsed.severity = Some("warning".to_string());
    }

    if parsed.statement_type.is_none() {
        parsed.statement_type = Some(classify_statement(message));
    }
    if parsed.client_ip.is_none() {
        parsed.client_ip = first_ipv4(message);
    }
    parsed.statement_summary = summarize_statement(message);

    Ok(build_event(
        path,
        line_number,
        line,
        DbType::MySql,
        parsed,
        0.78,
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
        .or_else(|| value.get("query"))
        .or_else(|| value.get("sql"))
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if timestamp.is_none() && statement.is_empty() {
        return Err("JSON database log missing timestamp and statement".to_string());
    }

    let parsed = ParsedDbLine {
        timestamp,
        db_user: value
            .get("user")
            .and_then(Value::as_str)
            .map(str::to_string),
        db_name: value
            .get("db")
            .or_else(|| value.get("database"))
            .and_then(Value::as_str)
            .map(str::to_string),
        client_ip: value
            .get("client_ip")
            .or_else(|| value.get("ip"))
            .and_then(Value::as_str)
            .map(str::to_string),
        session_id: value
            .get("session_id")
            .or_else(|| value.get("thread_id"))
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| value.as_i64().map(|number| number.to_string()))
            }),
        statement_type: Some(classify_statement(statement)),
        statement_summary: summarize_statement(statement),
        duration_ms: value
            .get("duration_ms")
            .or_else(|| value.get("query_time_ms"))
            .and_then(Value::as_f64),
        rows: value.get("rows").and_then(Value::as_u64),
        severity: value
            .get("severity")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..ParsedDbLine::default()
    };

    Ok(build_event(
        path,
        line_number,
        line,
        DbType::MySql,
        parsed,
        0.86,
    ))
}

fn take_session_id(value: &str) -> Option<(&str, &str)> {
    let mut parts = value.splitn(2, char::is_whitespace);
    let first = parts.next()?;
    if first.chars().all(|ch| ch.is_ascii_digit()) {
        Some((first, parts.next().unwrap_or_default()))
    } else {
        None
    }
}

fn take_command(value: &str) -> Option<(&str, &str)> {
    let mut parts = value.splitn(2, char::is_whitespace);
    let first = parts.next()?;
    let lower = first.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "query" | "connect" | "execute" | "prepare" | "quit" | "init" | "stmt_execute"
    ) {
        Some((first, parts.next().unwrap_or_default()))
    } else {
        None
    }
}

fn command_to_statement_type(command: &str, message: &str) -> String {
    let classified = classify_statement(message);
    if classified != "other" {
        return classified;
    }
    match command.to_ascii_lowercase().as_str() {
        "connect" => "connection".to_string(),
        "quit" => "disconnect".to_string(),
        _ => "query".to_string(),
    }
}
