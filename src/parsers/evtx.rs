use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use serde_json::Value;

use crate::model::WindowsEvent;
use crate::parsers::access_log::sha256_hex;

pub fn parse_windows_export(
    path: &Path,
    text: &str,
) -> (Vec<WindowsEvent>, Vec<(u64, String, String)>, u64) {
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return (Vec::new(), Vec::new(), 0);
    }

    if trimmed.starts_with('<') {
        return parse_xml_export(path, text);
    }
    parse_json_export(path, text)
}

fn parse_xml_export(
    path: &Path,
    text: &str,
) -> (Vec<WindowsEvent>, Vec<(u64, String, String)>, u64) {
    let blocks = event_xml_blocks(text);
    if blocks.is_empty() {
        return (
            Vec::new(),
            vec![(
                1,
                "could not find <Event> blocks in XML export".to_string(),
                safe_sample(text),
            )],
            text.lines().count() as u64,
        );
    }

    let mut events = Vec::new();
    let mut errors = Vec::new();
    for block in blocks {
        let line_number = line_number_for_offset(text, block.start);
        match parse_xml_event(path, line_number, block.content) {
            Ok(event) => events.push(event),
            Err(message) => errors.push((line_number, message, safe_sample(block.content))),
        }
    }
    (events, errors, text.lines().count() as u64)
}

fn parse_json_export(
    path: &Path,
    text: &str,
) -> (Vec<WindowsEvent>, Vec<(u64, String, String)>, u64) {
    let trimmed = text.trim();
    if trimmed.starts_with('[') {
        let mut events = Vec::new();
        let mut errors = Vec::new();
        match serde_json::from_str::<Value>(trimmed) {
            Ok(Value::Array(values)) => {
                for (index, value) in values.iter().enumerate() {
                    match event_from_json_value(path, index as u64 + 1, value, &value.to_string()) {
                        Ok(event) => events.push(event),
                        Err(message) => errors.push((index as u64 + 1, message, value.to_string())),
                    }
                }
            }
            Ok(value) => match event_from_json_value(path, 1, &value, trimmed) {
                Ok(event) => events.push(event),
                Err(message) => errors.push((1, message, safe_sample(trimmed))),
            },
            Err(error) => errors.push((
                1,
                format!("invalid JSON EVTX export: {error}"),
                safe_sample(trimmed),
            )),
        }
        return (events, errors, text.lines().count() as u64);
    }

    let mut events = Vec::new();
    let mut errors = Vec::new();
    let mut lines_seen = 0_u64;
    for (index, line) in text.lines().enumerate() {
        let line_number = index as u64 + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines_seen += 1;
        match serde_json::from_str::<Value>(line) {
            Ok(value) => match event_from_json_value(path, line_number, &value, line) {
                Ok(event) => events.push(event),
                Err(message) => errors.push((line_number, message, safe_sample(line))),
            },
            Err(error) => errors.push((
                line_number,
                format!("invalid JSONL EVTX record: {error}"),
                safe_sample(line),
            )),
        }
    }
    (events, errors, lines_seen)
}

fn parse_xml_event(
    path: &Path,
    line_number: u64,
    block: &str,
) -> std::result::Result<WindowsEvent, String> {
    let provider = provider_name(block);
    let event_code = text_between_tags(block, "EventID");
    if event_code.is_none() {
        return Err("missing EventID".to_string());
    }
    let timestamp = time_created(block);
    let channel = text_between_tags(block, "Channel");
    let computer = text_between_tags(block, "Computer");
    let severity = text_between_tags(block, "Level");
    let data = event_data_values(block);
    Ok(build_windows_event(
        path,
        line_number,
        block,
        provider,
        event_code,
        timestamp,
        channel,
        computer,
        severity,
        &data,
    ))
}

fn event_from_json_value(
    path: &Path,
    line_number: u64,
    value: &Value,
    raw: &str,
) -> std::result::Result<WindowsEvent, String> {
    let data = event_data_from_json(value);
    let provider = first_json_string(
        value,
        &["provider", "Provider", "provider_name", "ProviderName"],
    )
    .or_else(|| provider_from_json_system(value));
    let event_code = first_json_string(value, &["event_code", "event_id", "EventID", "Id", "id"])
        .or_else(|| json_pointer_string(value, &["System", "EventID"]))
        .or_else(|| json_pointer_string(value, &["system", "event_id"]));
    if event_code.is_none() {
        return Err("missing event id".to_string());
    }
    let timestamp = first_json_string(
        value,
        &[
            "timestamp",
            "time_created",
            "TimeCreated",
            "SystemTime",
            "EventTime",
        ],
    )
    .or_else(|| time_from_json_system(value));
    let channel = first_json_string(value, &["channel", "Channel", "LogName"])
        .or_else(|| json_pointer_string(value, &["System", "Channel"]));
    let computer = first_json_string(value, &["computer", "Computer", "ComputerName"])
        .or_else(|| json_pointer_string(value, &["System", "Computer"]));
    let severity = first_json_string(value, &["severity", "level", "Level"]);

    Ok(build_windows_event(
        path,
        line_number,
        raw,
        provider,
        event_code,
        timestamp,
        channel,
        computer,
        severity,
        &data,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_windows_event(
    path: &Path,
    line_number: u64,
    raw: &str,
    provider: Option<String>,
    event_code: Option<String>,
    timestamp: Option<String>,
    channel: Option<String>,
    computer: Option<String>,
    severity: Option<String>,
    data: &BTreeMap<String, String>,
) -> WindowsEvent {
    let raw_hash = sha256_hex(raw.as_bytes());
    let code = event_code.clone().unwrap_or_default();
    let action = action_for_event_code(&code).map(str::to_string);
    let result = result_for_event_code(&code).map(str::to_string);
    let command_line_summary = first_data(
        data,
        &[
            "CommandLine",
            "ProcessCommandLine",
            "ScriptBlockText",
            "Message",
            "Image",
        ],
    )
    .map(|value| summarize_command(&value));
    let process_name = first_data(
        data,
        &[
            "NewProcessName",
            "ProcessName",
            "Image",
            "Application",
            "ProcessPath",
        ],
    );
    let parent_process_name = first_data(
        data,
        &["ParentProcessName", "ParentImage", "CreatorProcessName"],
    );
    let service_name = first_data(data, &["ServiceName", "param1", "Service"]);
    let service_path = first_data(data, &["ImagePath", "ServiceFileName", "param2", "Path"]);
    let task_name = first_data(data, &["TaskName", "Task", "TaskContent"]);
    let object_path = service_path
        .clone()
        .or_else(|| first_data(data, &["ObjectName", "TargetObject", "Path"]));
    let user = first_data(
        data,
        &[
            "SubjectUserName",
            "User",
            "AccountName",
            "TargetUserName",
            "Security ID",
        ],
    );
    let target_user = first_data(data, &["TargetUserName", "AccountName", "TargetAccount"]);
    let source_ip = first_data(
        data,
        &[
            "IpAddress",
            "SourceNetworkAddress",
            "ClientAddress",
            "SourceAddress",
        ],
    )
    .filter(|value| value != "-" && value != "::1");
    let process_id = first_data(data, &["NewProcessId", "ProcessId", "ExecutionProcessID"]);

    WindowsEvent {
        event_id: format!("WIN-{}", &raw_hash[..16]),
        timestamp,
        channel,
        provider,
        event_code,
        computer,
        user,
        process_name,
        process_id,
        parent_process_name,
        command_line_summary,
        source_ip,
        target_user,
        service_name,
        task_name,
        object_path,
        action,
        result,
        severity,
        raw_hash,
        parser_confidence: 0.9,
        source_file: path.display().to_string(),
        line_number,
    }
}

fn action_for_event_code(code: &str) -> Option<&'static str> {
    match code {
        "4624" => Some("logon_success"),
        "4625" => Some("logon_failure"),
        "4648" => Some("explicit_credentials"),
        "4672" => Some("special_privileges"),
        "4688" => Some("process_create"),
        "4103" | "4104" => Some("powershell"),
        "7045" => Some("service_install"),
        "4698" | "106" => Some("scheduled_task_create"),
        "4697" => Some("service_install"),
        "4699" => Some("scheduled_task_delete"),
        "4700" => Some("scheduled_task_enable"),
        "4701" => Some("scheduled_task_disable"),
        "4702" | "140" => Some("scheduled_task_update"),
        "4720" => Some("user_create"),
        "4728" | "4732" | "4756" => Some("group_add"),
        "4768" => Some("kerberos_tgt_request"),
        "4769" => Some("kerberos_service_ticket"),
        "4771" => Some("kerberos_preauth_failure"),
        "5140" | "5145" => Some("smb_share_access"),
        "4657" => Some("registry_value_change"),
        "4719" => Some("audit_policy_change"),
        "4946" | "4947" | "4948" | "4950" | "4951" => Some("firewall_policy_change"),
        "1102" | "104" => Some("log_clear"),
        "6005" => Some("event_log_service_start"),
        "6006" => Some("event_log_service_stop"),
        "1000" => Some("application_crash"),
        "1001" => Some("windows_error_report"),
        "11707" => Some("msi_install_complete"),
        "1116" | "1117" => Some("defender_detection"),
        "1149" | "21" | "24" | "25" => Some("rdp_activity"),
        "5857" | "5858" => Some("wmi_activity"),
        "7036" => Some("service_state_change"),
        "6008" | "41" => Some("unexpected_shutdown"),
        _ => None,
    }
}

fn result_for_event_code(code: &str) -> Option<&'static str> {
    match code {
        "4624" => Some("success"),
        "4625" => Some("failure"),
        _ => None,
    }
}

fn provider_name(block: &str) -> Option<String> {
    let regex = Regex::new(r#"(?is)<Provider\b[^>]*\bName\s*=\s*["']([^"']+)["']"#).ok()?;
    regex
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml(value.as_str()))
}

fn time_created(block: &str) -> Option<String> {
    let regex =
        Regex::new(r#"(?is)<TimeCreated\b[^>]*\bSystemTime\s*=\s*["']([^"']+)["']"#).ok()?;
    regex
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml(value.as_str()))
}

fn text_between_tags(block: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"(?is)<{tag}\b[^>]*>(.*?)</{tag}>");
    let regex = Regex::new(&pattern).ok()?;
    regex
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml(value.as_str()))
        .filter(|value| !value.trim().is_empty())
}

fn event_data_values(block: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let Ok(regex) =
        Regex::new(r#"(?is)<Data\b[^>]*\bName\s*=\s*["']([^"']+)["'][^>]*>(.*?)</Data>"#)
    else {
        return values;
    };
    for captures in regex.captures_iter(block) {
        let Some(name) = captures.get(1).map(|value| decode_xml(value.as_str())) else {
            continue;
        };
        let value = captures
            .get(2)
            .map(|value| decode_xml(value.as_str()))
            .unwrap_or_default();
        if !name.is_empty() && !value.is_empty() {
            values.insert(name, value);
        }
    }
    values
}

fn event_data_from_json(value: &Value) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    flatten_json("", value, &mut output);
    if let Some(event_data) = value.get("EventData").or_else(|| value.get("event_data")) {
        if let Some(data) = event_data.get("Data").or_else(|| event_data.get("data")) {
            match data {
                Value::Array(items) => {
                    for item in items {
                        let name = first_json_string(item, &["Name", "name"])
                            .or_else(|| item.get("@Name").and_then(json_scalar_string));
                        let text = first_json_string(item, &["#text", "text", "Value", "value"])
                            .or_else(|| item.get("$").and_then(json_scalar_string));
                        if let (Some(name), Some(text)) = (name, text) {
                            output.insert(name, text);
                        }
                    }
                }
                Value::Object(map) => {
                    for (key, value) in map {
                        if let Some(text) = json_scalar_string(value) {
                            output.insert(key.clone(), text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    output
}

fn flatten_json(prefix: &str, value: &Value, output: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json(&next, child, output);
            }
        }
        Value::Array(_) => {}
        _ => {
            if let Some(text) = json_scalar_string(value) {
                let key = prefix.rsplit('.').next().unwrap_or(prefix).to_string();
                output.entry(key).or_insert(text);
            }
        }
    }
}

fn first_data(data: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        data.iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn first_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(json_scalar_string) {
            return Some(text);
        }
    }
    None
}

fn provider_from_json_system(value: &Value) -> Option<String> {
    let provider = value.get("System")?.get("Provider")?;
    first_json_string(provider, &["Name", "name", "@Name"])
}

fn time_from_json_system(value: &Value) -> Option<String> {
    let time_created = value.get("System")?.get("TimeCreated")?;
    first_json_string(time_created, &["SystemTime", "system_time", "@SystemTime"])
}

fn json_pointer_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    json_scalar_string(current)
}

fn json_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()).filter(|value| !value.is_empty()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

struct XmlBlock<'a> {
    start: usize,
    content: &'a str,
}

fn event_xml_blocks(text: &str) -> Vec<XmlBlock<'_>> {
    let Ok(regex) = Regex::new(r"(?is)<Event\b[^>]*>.*?</Event>") else {
        return Vec::new();
    };
    regex
        .find_iter(text)
        .map(|item| XmlBlock {
            start: item.start(),
            content: item.as_str(),
        })
        .collect()
}

fn line_number_for_offset(text: &str, offset: usize) -> u64 {
    text[..offset].bytes().filter(|byte| *byte == b'\n').count() as u64 + 1
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

fn safe_sample(value: &str) -> String {
    safe_prefix(value.trim(), 200).to_string()
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

fn decode_xml(value: &str) -> String {
    value
        .trim()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}
