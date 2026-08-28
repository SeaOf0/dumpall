//! /etc/sudoers 与 sudoers.d 采集：解析授权行并标记 NOPASSWD、全量授权等高危项。

use std::fs;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::push_collection_error;

const HEADER: &str = "source_file,line_no,user,host,runas,commands,flags,mtime\n";

#[derive(Debug, Clone, Serialize)]
struct SudoersRow {
    source_file: String,
    line_no: u64,
    user: String,
    host: String,
    runas: String,
    commands: String,
    flags: String,
    mtime: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let mut rows = Vec::new();
    parse_file("/etc/sudoers", &mut rows);
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map(|ext| ext == "sudoers")
                .unwrap_or(false)
                || entry.file_type().map(|t| t.is_file()).unwrap_or(false)
            {
                parse_file(&path.display().to_string(), &mut rows);
            }
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.sudoers, HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.sudoers, &rows)?;
    }
    if rows.is_empty() && std::path::Path::new("/etc/sudoers").exists() {
        push_collection_error(
            errors,
            "sudoers",
            "/etc/sudoers",
            "read_sudoers",
            "sudoers exists but no rules parsed (permission or empty)",
            None,
        );
    }
    Ok(())
}

fn parse_file(source: &str, rows: &mut Vec<SudoersRow>) {
    let path = std::path::Path::new(source);
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let mtime = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map(crate::time_utils::system_time_to_iso)
        .unwrap_or_default();
    for (index, line) in content.lines().enumerate() {
        let trimmed = strip_continuation(line.trim());
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("@") {
            // @include/@includedir 由显式扫描 sudoers.d 覆盖。
            continue;
        }
        if let Some(rule) = parse_rule(trimmed, source, (index + 1) as u64, &mtime) {
            rows.push(rule);
        }
    }
}

/// 去掉行尾续行符，采集侧不跨行合并（保守记录原始行语义）。
fn strip_continuation(line: &str) -> &str {
    line.strip_suffix('\\').unwrap_or(line).trim()
}

fn parse_rule(line: &str, source: &str, line_no: u64, mtime: &str) -> Option<SudoersRow> {
    // Defaults 行与别名定义（User_Alias/Cmnd_Alias 等）整体登记为配置行。
    if line.starts_with("Defaults") || line.contains("_Alias") {
        return Some(SudoersRow {
            source_file: source.to_string(),
            line_no,
            user: String::new(),
            host: String::new(),
            runas: String::new(),
            commands: truncate(line, 300).to_string(),
            flags: "defaults_or_alias".to_string(),
            mtime: mtime.to_string(),
        });
    }
    // 格式：user host = (runas) commands 或 user host = commands 或 user host commands
    let mut rest = line;
    let user = rest.split_whitespace().next()?.to_string();
    // user 是 rest 的前缀（无前导空白），按长度切片安全。
    rest = rest[user.len()..].trim_start();
    // host 以 '='、'(' 或空白结束。
    let host_end = rest
        .find(|c: char| c == '=' || c == '(' || c.is_whitespace())
        .unwrap_or(rest.len());
    let host = rest[..host_end].to_string();
    rest = rest[host_end..].trim_start();
    // 语法中的赋值等号：host = (runas) commands。
    if let Some(after_eq) = rest.strip_prefix('=') {
        rest = after_eq.trim_start();
    }
    let mut runas = String::new();
    if rest.starts_with('(') {
        if let Some(close) = rest.find(')') {
            runas = rest[1..close].to_string();
            rest = rest[close + 1..].trim_start();
        }
    }
    let commands = truncate(rest, 400).to_string();
    let mut flags = Vec::new();
    let lower = rest.to_ascii_lowercase();
    if lower.contains("nopasswd") {
        flags.push("nopasswd");
    }
    if lower.contains("noexec:off") {
        flags.push("noexec_off");
    }
    if host == "ALL"
        && (runas == "ALL" || runas.starts_with("ALL") || runas.is_empty())
        && rest.trim() == "ALL"
    {
        flags.push("full_grant");
    }
    if lower.contains("setenv") {
        flags.push("setenv");
    }
    Some(SudoersRow {
        source_file: source.to_string(),
        line_no,
        user,
        host,
        runas,
        commands,
        flags: flags.join("|"),
        mtime: mtime.to_string(),
    })
}

fn truncate(value: &str, max: usize) -> &str {
    value.get(..max).unwrap_or_else(|| {
        let mut end = max.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_rule_with_nopasswd() {
        let rule = parse_rule(
            "www-data ALL=(ALL) NOPASSWD: /usr/bin/curl",
            "/etc/sudoers",
            3,
            "",
        )
        .unwrap();
        assert_eq!(rule.user, "www-data");
        assert_eq!(rule.host, "ALL");
        assert_eq!(rule.runas, "ALL");
        assert!(rule.flags.contains("nopasswd"));
    }

    #[test]
    fn parses_rule_without_runas() {
        let rule = parse_rule("%sudo ALL=(ALL:ALL) ALL", "/etc/sudoers", 1, "").unwrap();
        assert_eq!(rule.user, "%sudo");
        assert!(rule.flags.contains("full_grant"));
    }

    #[test]
    fn defaults_line_kept_as_flag_row() {
        let rule =
            parse_rule("Defaults env_keep += \"http_proxy\"", "/etc/sudoers", 9, "").unwrap();
        assert_eq!(rule.flags, "defaults_or_alias");
    }
}
