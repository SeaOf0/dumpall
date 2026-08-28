//! 进程环境变量采集：/proc/<pid>/environ（NUL 分隔），受 --redact 脱敏控制。

use std::fs;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const HEADER: &str = "pid,user,var_count,variables\n";
/// 单进程最多保留的环境变量字符数。
const MAX_ENV_CHARS: usize = 8_192;

#[derive(Debug, Clone, Serialize)]
struct ProcessEnvRow {
    pid: String,
    user: String,
    var_count: String,
    variables: String,
}

pub fn collect(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    let mut rows = Vec::new();
    let uid_map = uid_name_map();
    let Ok(entries) = fs::read_dir("/proc") else {
        errors.push(super::collection_error(
            "process_env",
            "/proc",
            "read_proc",
            "process list could not be read",
            None,
        ));
        return writers::write_text(&layout.process_env, HEADER);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // environ 只对进程属主或 root 可读，读不到时静默跳过（正常权限行为）。
        let Ok(raw) = fs::read(entry.path().join("environ")) else {
            continue;
        };
        let vars: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf8_lossy(entry).to_string())
            .collect();
        let uid = fs::read_to_string(entry.path().join("status"))
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    let rest = line.strip_prefix("Uid:")?;
                    rest.split_whitespace().next().map(|v| v.to_string())
                })
            })
            .unwrap_or_default();
        let mut joined = vars.join(" | ");
        if redact {
            joined = crate::safety::redact_text(&joined);
        }
        if joined.len() > MAX_ENV_CHARS {
            let mut end = MAX_ENV_CHARS;
            while end > 0 && !joined.is_char_boundary(end) {
                end -= 1;
            }
            joined.truncate(end);
            joined.push_str("...(truncated)");
        }
        rows.push(ProcessEnvRow {
            pid: name,
            user: uid_map.get(&uid).cloned().unwrap_or(uid),
            var_count: vars.len().to_string(),
            variables: joined,
        });
    }
    if rows.is_empty() {
        writers::write_text(&layout.process_env, HEADER)
    } else {
        writers::write_csv_serialize(&layout.process_env, &rows)
    }
}

fn uid_name_map() -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                map.insert(fields[2].to_string(), fields[0].to_string());
            }
        }
    }
    map
}
