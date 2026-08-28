use std::path::Path;

use serde_json::Value;

use crate::model::ContainerLogEvent;
use crate::parsers::access_log::sha256_hex;

pub fn parse_container_log_line(
    path: &Path,
    line_number: u64,
    line: &str,
    runtime: &str,
) -> std::result::Result<Option<ContainerLogEvent>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<Value>(trimmed)
            .map_err(|error| format!("invalid container log JSON record: {error}"))?;
        return Ok(Some(event_from_json(
            path,
            line_number,
            trimmed,
            runtime,
            &value,
        )));
    }
    Ok(Some(event_from_text(path, line_number, trimmed, runtime)))
}

fn event_from_json(
    path: &Path,
    line_number: u64,
    raw: &str,
    runtime: &str,
    value: &Value,
) -> ContainerLogEvent {
    let raw_hash = sha256_hex(raw.as_bytes());
    let message = first_string(
        value,
        &["log", "message", "msg", "MESSAGE", "content", "line"],
    )
    .unwrap_or_else(|| raw.to_string());
    ContainerLogEvent {
        event_id: format!("CTR-LOG-{}", &raw_hash[..16]),
        timestamp: first_string(value, &["time", "timestamp", "@timestamp", "ts"]),
        runtime: runtime.to_string(),
        container_id: first_string(value, &["container_id", "containerID", "id"]),
        container_name: first_string(value, &["container_name", "container", "name"]),
        pod_name: first_string(value, &["pod_name", "pod", "kubernetes.pod_name"]),
        namespace: first_string(value, &["namespace", "kubernetes.namespace_name"]),
        stream: first_string(value, &["stream", "source"]),
        message_summary: summarize(&message),
        source_file: path.display().to_string(),
        line_number,
        raw_hash,
        parser_confidence: 0.85,
    }
}

fn event_from_text(path: &Path, line_number: u64, raw: &str, runtime: &str) -> ContainerLogEvent {
    let raw_hash = sha256_hex(raw.as_bytes());
    let timestamp = raw
        .split_whitespace()
        .next()
        .filter(|value| value.contains('T') || value.contains('-'))
        .map(str::to_string);
    ContainerLogEvent {
        event_id: format!("CTR-LOG-{}", &raw_hash[..16]),
        timestamp,
        runtime: runtime.to_string(),
        container_id: None,
        container_name: None,
        pod_name: None,
        namespace: None,
        stream: None,
        message_summary: summarize(raw),
        source_file: path.display().to_string(),
        line_number,
        raw_hash,
        parser_confidence: 0.65,
    }
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(json_scalar_string) {
            return Some(text);
        }
        if key.contains('.') {
            if let Some(text) = dotted_value(value, key).and_then(json_scalar_string) {
                return Some(text);
            }
        }
    }
    None
}

fn dotted_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in key.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn json_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()).filter(|text| !text.is_empty()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn summarize(value: &str) -> String {
    const MAX: usize = 300;
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
