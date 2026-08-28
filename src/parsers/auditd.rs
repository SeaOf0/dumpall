use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use time::OffsetDateTime;

use crate::model::LinuxEvent;
use crate::parsers::access_log::sha256_hex;

pub fn parse_audit_or_auth_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<Option<LinuxEvent>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.contains("type=") && trimmed.contains("msg=audit(") {
        return Ok(Some(parse_auditd_line(path, line_number, trimmed)?));
    }
    if let Some(event) = parse_auth_line(path, line_number, trimmed) {
        return Ok(Some(event));
    }
    Ok(None)
}

fn parse_auditd_line(
    path: &Path,
    line_number: u64,
    line: &str,
) -> std::result::Result<LinuxEvent, String> {
    let fields = key_values(line);
    let event_type = fields
        .get("type")
        .cloned()
        .or_else(|| {
            line.split_whitespace()
                .next()
                .and_then(|part| part.strip_prefix("type="))
                .map(str::to_string)
        })
        .unwrap_or_default();
    if event_type.is_empty() {
        return Err("missing auditd type".to_string());
    }
    let raw_hash = sha256_hex(line.as_bytes());
    let command_line_summary = if event_type.eq_ignore_ascii_case("EXECVE") {
        Some(execve_command(&fields))
    } else {
        fields
            .get("cmd")
            .or_else(|| fields.get("command"))
            .map(|value| summarize_command(value))
    };
    let process_name = fields
        .get("comm")
        .or_else(|| fields.get("exe"))
        .map(|value| trim_path_or_quotes(value));
    let user = fields
        .get("acct")
        .or_else(|| fields.get("user"))
        .cloned()
        .or_else(|| fields.get("uid").map(|uid| uid_to_userish(uid)));
    let action = match event_type.as_str() {
        "EXECVE" => "execve",
        "SYSCALL" => "syscall",
        "USER_LOGIN" | "USER_AUTH" | "CRED_ACQ" => "auth",
        _ => {
            return Ok(generic_audit_event(
                path,
                line_number,
                line,
                event_type,
                fields,
                raw_hash,
            ))
        }
    }
    .to_string();
    let result = fields
        .get("success")
        .map(|value| if value == "yes" { "success" } else { "failure" }.to_string())
        .or_else(|| fields.get("res").cloned());

    Ok(LinuxEvent {
        event_id: format!("LNX-{}", &raw_hash[..16]),
        timestamp: audit_timestamp(line),
        source: Some("auditd".to_string()),
        unit: None,
        user,
        uid: fields.get("uid").cloned(),
        pid: fields.get("pid").cloned(),
        ppid: fields.get("ppid").cloned(),
        process_name,
        command_line_summary,
        cwd: fields.get("cwd").cloned(),
        src_ip: fields.get("addr").or_else(|| fields.get("src")).cloned(),
        tty: fields.get("tty").cloned(),
        session: fields.get("ses").cloned(),
        action: Some(action),
        object_path: fields.get("exe").or_else(|| fields.get("path")).cloned(),
        result,
        raw_hash,
        parser_confidence: 0.85,
        source_file: path.display().to_string(),
        line_number,
    })
}

fn generic_audit_event(
    path: &Path,
    line_number: u64,
    line: &str,
    event_type: String,
    fields: BTreeMap<String, String>,
    raw_hash: String,
) -> LinuxEvent {
    LinuxEvent {
        event_id: format!("LNX-{}", &raw_hash[..16]),
        timestamp: audit_timestamp(line),
        source: Some("auditd".to_string()),
        unit: None,
        user: fields
            .get("acct")
            .or_else(|| fields.get("user"))
            .cloned()
            .or_else(|| fields.get("uid").map(|uid| uid_to_userish(uid))),
        uid: fields.get("uid").cloned(),
        pid: fields.get("pid").cloned(),
        ppid: fields.get("ppid").cloned(),
        process_name: fields
            .get("comm")
            .or_else(|| fields.get("exe"))
            .map(|value| trim_path_or_quotes(value)),
        command_line_summary: fields.get("cmd").map(|value| summarize_command(value)),
        cwd: fields.get("cwd").cloned(),
        src_ip: fields.get("addr").or_else(|| fields.get("src")).cloned(),
        tty: fields.get("tty").cloned(),
        session: fields.get("ses").cloned(),
        action: Some(event_type.to_ascii_lowercase()),
        object_path: fields.get("exe").or_else(|| fields.get("path")).cloned(),
        result: fields
            .get("success")
            .map(|value| if value == "yes" { "success" } else { "failure" }.to_string())
            .or_else(|| fields.get("res").cloned()),
        raw_hash,
        parser_confidence: 0.75,
        source_file: path.display().to_string(),
        line_number,
    }
}

fn parse_auth_line(path: &Path, line_number: u64, line: &str) -> Option<LinuxEvent> {
    let lower = line.to_ascii_lowercase();
    let raw_hash = sha256_hex(line.as_bytes());
    let mut event = LinuxEvent {
        event_id: format!("LNX-{}", &raw_hash[..16]),
        timestamp: leading_timestamp(line),
        source: Some("auth_log".to_string()),
        unit: None,
        user: None,
        uid: None,
        pid: pid_from_syslog(line),
        ppid: None,
        process_name: process_from_syslog(line),
        command_line_summary: None,
        cwd: None,
        src_ip: None,
        tty: None,
        session: None,
        action: None,
        object_path: None,
        result: None,
        raw_hash,
        parser_confidence: 0.75,
        source_file: path.display().to_string(),
        line_number,
    };

    if lower.contains("failed password") {
        event.action = Some("login_failed".to_string());
        event.result = Some("failure".to_string());
        event.user = user_after_for(line);
        event.src_ip = ip_after_from(line);
        return Some(event);
    }
    if lower.contains("accepted password") || lower.contains("accepted publickey") {
        event.action = Some("login_success".to_string());
        event.result = Some("success".to_string());
        event.user = user_after_for(line);
        event.src_ip = ip_after_from(line);
        return Some(event);
    }
    if lower.contains("sudo:") && lower.contains("command=") {
        event.action = Some("sudo".to_string());
        event.result = Some("success".to_string());
        event.user = sudo_user(line);
        event.command_line_summary =
            field_after_marker(line, "COMMAND=").map(|value| summarize_command(&value));
        event.object_path.clone_from(&event.command_line_summary);
        return Some(event);
    }
    if lower.contains("cron[") && lower.contains(" cmd ")
        || lower.contains("cron[") && lower.contains("cmd (")
    {
        event.action = Some("cron".to_string());
        event.command_line_summary = cron_command(line);
        event.object_path.clone_from(&event.command_line_summary);
        return Some(event);
    }
    if lower.contains("systemd")
        && (lower.contains("started ") || lower.contains("failed to start "))
    {
        event.action = Some(
            if lower.contains("failed to start ") {
                "service_failed"
            } else {
                "service_started"
            }
            .to_string(),
        );
        event.unit = service_unit_from_message(line);
        event.object_path.clone_from(&event.unit);
        return Some(event);
    }
    None
}

fn key_values(line: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let Ok(regex) = Regex::new(r#"([A-Za-z0-9_]+)=("[^"]*"|'[^']*'|[^\s]+)"#) else {
        return values;
    };
    for captures in regex.captures_iter(line) {
        let Some(key) = captures.get(1).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let value = captures
            .get(2)
            .map(|value| trim_quotes(value.as_str()).to_string())
            .unwrap_or_default();
        values.insert(key, value);
    }
    values
}

fn execve_command(fields: &BTreeMap<String, String>) -> String {
    let mut indexed = fields
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix('a')
                .and_then(|suffix| suffix.parse::<usize>().ok())
                .map(|index| (index, decode_execve_arg(value)))
        })
        .collect::<Vec<_>>();
    indexed.sort_by_key(|(index, _)| *index);
    summarize_command(
        &indexed
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// auditd 会把含空格/引号/非 ASCII 的 EXECVE 参数编成十六进制(a0=63617420...):
/// 未加引号、偶数长度、纯 hex 且解码后可打印占比高时还原为文本再拼接,
/// 避免命令行摘要只剩一串不可读 hex;带引号参数由 key_values 阶段去引号。
fn decode_execve_arg(value: &str) -> String {
    let is_hex = value.len() >= 4
        && value.len() % 2 == 0
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f' | 'A'..='F'));
    if !is_hex {
        return value.to_string();
    }
    let decoded: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap_or(0))
        .collect();
    let printable = decoded
        .iter()
        .filter(|&&byte| (0x20..=0x7e).contains(&byte) || byte >= 0x80)
        .count();
    let ratio = printable as f64 / decoded.len() as f64;
    // 解码结果须大体可打印;且"含空白且 >= 4 字节"或">= 6 字节",
    // 排除 "2026"(→" &")这类偶合的短数字串误解码。
    let plausible = ratio >= 0.9
        && ((decoded.iter().any(|&byte| byte == b' ') && decoded.len() >= 4)
            || decoded.len() >= 6);
    if plausible {
        String::from_utf8_lossy(&decoded).into_owned()
    } else {
        value.to_string()
    }
}

fn audit_timestamp(line: &str) -> Option<String> {
    let regex = Regex::new(r"msg=audit\((\d+)(?:\.\d+)?:\d+\)").ok()?;
    let seconds = regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<i64>().ok())?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .map(crate::time_utils::format_iso)
}

fn leading_timestamp(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    if first.contains('T') {
        return line.split_whitespace().next().map(str::to_string);
    }
    // 传统 syslog 时间戳 "Mon DD HH:MM:SS"(auth.log/secure 默认格式):
    // 借助 time_utils 按当前时间推断年份(跨年回退),规范化为 ISO 串。
    let second = parts.next()?;
    let third = parts.next()?;
    crate::time_utils::parse_syslog_timestamp(&format!("{first} {second} {third}"))
        .map(crate::time_utils::format_iso)
}

fn pid_from_syslog(line: &str) -> Option<String> {
    let regex = Regex::new(r"\[(\d+)\]:").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn process_from_syslog(line: &str) -> Option<String> {
    let regex = Regex::new(r"\s([A-Za-z0-9_.-]+)(?:\[\d+\])?:").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn user_after_for(line: &str) -> Option<String> {
    let regex = Regex::new(r"\bfor (?:invalid user )?([^\s]+)").ok()?;
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

fn sudo_user(line: &str) -> Option<String> {
    let regex = Regex::new(r"sudo:\s+([^:]+)\s+:").ok()?;
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
}

fn field_after_marker(line: &str, marker: &str) -> Option<String> {
    let (_, value) = line.split_once(marker)?;
    Some(value.trim().to_string()).filter(|value| !value.is_empty())
}

fn cron_command(line: &str) -> Option<String> {
    let start = line.find("CMD")?;
    Some(line[start..].trim().to_string())
}

fn service_unit_from_message(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let started = "started ".len();
    let failed = "failed to start ".len();
    let marker = if let Some(pos) = lower.find("started ") {
        pos + started
    } else {
        lower.find("failed to start ")? + failed
    };
    Some(
        line[marker..]
            .trim()
            .trim_end_matches('.')
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string(),
    )
    .filter(|value| !value.is_empty())
}

fn uid_to_userish(uid: &str) -> String {
    match uid {
        "33" => "www-data".to_string(),
        "48" => "apache".to_string(),
        value => format!("uid={value}"),
    }
}

fn trim_path_or_quotes(value: &str) -> String {
    trim_quotes(value)
        .rsplit('/')
        .next()
        .unwrap_or(value)
        .to_string()
}

fn trim_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
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
    fn auth_line_with_traditional_syslog_timestamp() {
        // 传统 syslog 时间戳(无年份):推断年份并规范化为 ISO,不再是 None
        let event = parse_audit_or_auth_line(
            Path::new("auth.log"),
            1,
            "May 15 08:00:01 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 51234 ssh2",
        )
        .unwrap()
        .expect("auth event parsed");
        let timestamp = event.timestamp.expect("timestamp resolved");
        assert!(timestamp.contains("T08:00:01"), "timestamp was {timestamp}");
        assert_eq!(event.action.as_deref(), Some("login_failed"));
        assert_eq!(event.src_ip.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn execve_hex_arguments_are_decoded() {
        // 2f6574632f706173737764 解码为 "/etc/passwd",2f6465762f6e756c6c 解码为 "/dev/null"
        let line = r#"type=EXECVE msg=audit(1747296000.123:456): pid=100 exe="/usr/bin/cat" a0=cat a1=2f6574632f706173737764 a2=2f6465762f6e756c6c"#;
        let event = parse_audit_or_auth_line(Path::new("audit.log"), 1, line)
            .unwrap()
            .expect("execve event parsed");
        let summary = event.command_line_summary.unwrap_or_default();
        assert!(
            summary.contains("cat /etc/passwd"),
            "summary was {summary}"
        );
        assert!(summary.contains("/dev/null"), "summary was {summary}");
    }

    #[test]
    fn execve_plain_arguments_not_mangled() {
        // 普通参数与偶合数字串("2026" 不应被误解码)保持原样
        let line = r#"type=EXECVE msg=audit(1747296000.123:457): pid=101 exe="/bin/sh" a0="sh" a1="-c" a2=2026 a3=31323334353637"#;
        let event = parse_audit_or_auth_line(Path::new("audit.log"), 1, line)
            .unwrap()
            .expect("execve event parsed");
        let summary = event.command_line_summary.unwrap_or_default();
        assert!(summary.contains("sh -c"), "summary was {summary}");
        assert!(summary.contains("2026"), "summary was {summary}");
    }
}
