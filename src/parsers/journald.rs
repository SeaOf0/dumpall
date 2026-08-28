use std::path::Path;

use regex::Regex;
use serde_json::Value;
use time::OffsetDateTime;

use crate::model::LinuxEvent;
use crate::parsers::access_log::sha256_hex;

pub fn parse_journal_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<Option<LinuxEvent>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<Value>(trimmed)
            .map_err(|error| format!("invalid journald JSON record: {error}"))?;
        return Ok(Some(parse_json_journal(path, line_number, &value, trimmed)));
    }
    Ok(parse_text_journal(path, line_number, trimmed))
}

fn parse_json_journal(path: &Path, line_number: u64, value: &Value, raw: &str) -> LinuxEvent {
    let raw_hash = sha256_hex(raw.as_bytes());
    let message = string_value(value, "MESSAGE");
    let unit = string_value(value, "_SYSTEMD_UNIT")
        .or_else(|| string_value(value, "UNIT"))
        .or_else(|| service_unit_from_message(message.as_deref().unwrap_or_default()));
    let action = action_from_message(message.as_deref().unwrap_or_default());
    LinuxEvent {
        event_id: format!("LNX-{}", &raw_hash[..16]),
        timestamp: journal_timestamp(value),
        source: Some("journald".to_string()),
        unit,
        user: string_value(value, "_UID").map(|uid| uid_to_userish(&uid)),
        uid: string_value(value, "_UID"),
        pid: string_value(value, "_PID"),
        ppid: None,
        process_name: string_value(value, "_COMM")
            .or_else(|| string_value(value, "SYSLOG_IDENTIFIER")),
        command_line_summary: message.clone().map(|value| summarize_command(&value)),
        cwd: None,
        src_ip: None,
        tty: None,
        session: None,
        action,
        object_path: message,
        result: None,
        raw_hash,
        parser_confidence: 0.8,
        source_file: path.display().to_string(),
        line_number,
    }
}

fn parse_text_journal(path: &Path, line_number: u64, line: &str) -> Option<LinuxEvent> {
    let lower = line.to_ascii_lowercase();
    if !(lower.contains("systemd")
        || lower.contains("sshd")
        || lower.contains("cron")
        || lower.contains("sudo"))
    {
        return None;
    }
    let raw_hash = sha256_hex(line.as_bytes());
    let message = message_after_colon(line).unwrap_or_else(|| line.to_string());
    Some(LinuxEvent {
        event_id: format!("LNX-{}", &raw_hash[..16]),
        timestamp: text_timestamp(line),
        source: Some("journald".to_string()),
        unit: service_unit_from_message(&message),
        user: None,
        uid: None,
        pid: pid_from_text(line),
        ppid: None,
        process_name: process_from_text(line),
        command_line_summary: Some(summarize_command(&message)),
        cwd: None,
        src_ip: ip_after_from(line),
        tty: None,
        session: None,
        action: action_from_message(&message),
        object_path: Some(message),
        result: None,
        raw_hash,
        parser_confidence: 0.7,
        source_file: path.display().to_string(),
        line_number,
    })
}

fn journal_timestamp(value: &Value) -> Option<String> {
    if let Some(text) =
        string_value(value, "timestamp").or_else(|| string_value(value, "__REALTIME_TIMESTAMP"))
    {
        if text.contains('T') {
            return Some(text);
        }
        if let Ok(micros) = text.parse::<i128>() {
            let seconds = (micros / 1_000_000) as i64;
            return OffsetDateTime::from_unix_timestamp(seconds)
                .ok()
                .map(crate::time_utils::format_iso);
        }
    }
    string_value(value, "_SOURCE_REALTIME_TIMESTAMP").and_then(|text| {
        text.parse::<i128>()
            .ok()
            .and_then(|micros| {
                OffsetDateTime::from_unix_timestamp((micros / 1_000_000) as i64).ok()
            })
            .map(crate::time_utils::format_iso)
    })
}

fn string_value(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(text) => Some(text.trim().to_string()).filter(|text| !text.is_empty()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn action_from_message(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    if lower.contains("failed to start ") {
        Some("service_failed".to_string())
    } else if lower.contains("started ") {
        Some("service_started".to_string())
    } else if lower.contains("accepted password") || lower.contains("accepted publickey") {
        Some("login_success".to_string())
    } else if lower.contains("failed password") {
        Some("login_failed".to_string())
    } else if lower.contains("sudo") {
        Some("sudo".to_string())
    } else if lower.contains("cron") {
        Some("cron".to_string())
    } else {
        None
    }
}

fn service_unit_from_message(message: &str) -> Option<String> {
    let regex = Regex::new(r"(?i)\b([A-Za-z0-9_.@-]+\.(?:service|timer|socket))\b").ok()?;
    regex
        .captures(message)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn message_after_colon(line: &str) -> Option<String> {
    line.split_once(": ")
        .map(|(_, message)| message.to_string())
}

/// 文本 journald 行的时间戳:ISO(含 T)直接保留;
/// 传统 syslog 格式 "Mon DD HH:MM:SS"(journalctl 短格式导出)借助
/// time_utils 按当前时间推断年份后规范化为 ISO,不再返回 None。
fn text_timestamp(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if first.contains('T') {
        return Some(first.to_string());
    }
    let second = parts.next()?;
    let third = parts.next()?;
    crate::time_utils::parse_syslog_timestamp(&format!("{first} {second} {third}"))
        .map(crate::time_utils::format_iso)
}

fn pid_from_text(line: &str) -> Option<String> {
    let regex = Regex::new(r"\[(\d+)\]:").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn process_from_text(line: &str) -> Option<String> {
    let regex = Regex::new(r"\s([A-Za-z0-9_.@-]+)(?:\[\d+\])?:").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn ip_after_from(line: &str) -> Option<String> {
    let regex = Regex::new(r"\bfrom ([0-9a-fA-F:.]+)").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn uid_to_userish(uid: &str) -> String {
    match uid {
        "33" => "www-data".to_string(),
        "48" => "apache".to_string(),
        value => format!("uid={value}"),
    }
}

fn summarize_command(value: &str) -> String {
    const MAX: usize = 240;
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() <= MAX {
        collapsed
    } else {
        format!("{}...", safe_prefix(&collapsed, MAX))
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
    fn text_journal_with_traditional_syslog_timestamp() {
        // journalctl 短格式导出:传统 syslog 时间戳推断年份并规范化为 ISO
        let event = parse_journal_line(
            Path::new("journal.log"),
            1,
            "May 15 08:00:01 web01 systemd[1]: Started nginx.service.",
        )
        .unwrap()
        .expect("journald event parsed");
        let timestamp = event.timestamp.expect("timestamp resolved");
        assert!(timestamp.contains("T08:00:01"), "timestamp was {timestamp}");
        assert_eq!(event.action.as_deref(), Some("service_started"));
        assert_eq!(event.unit.as_deref(), Some("nginx.service"));
    }

    #[test]
    fn iso_timestamp_line_still_untouched() {
        let event = parse_journal_line(
            Path::new("journal.log"),
            1,
            "2026-05-15T08:00:01Z web01 sudo[445]: session opened for root",
        )
        .unwrap()
        .expect("journald event parsed");
        assert_eq!(event.timestamp.as_deref(), Some("2026-05-15T08:00:01Z"));
    }
}
