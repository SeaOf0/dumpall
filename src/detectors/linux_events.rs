use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{EvidenceQuality, Finding, LinuxEvent, ScoreBreakdown, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::RunLogger;

pub const RULE_CATEGORY: &str = "host_linux_execution";

#[derive(Debug, Default)]
pub struct LinuxEventDetectionReport {
    pub findings: Vec<Finding>,
    pub rows_seen: usize,
    /// 事件 jsonl 中无法反序列化的坏行数（跳过但计数，不再静默丢弃）。
    pub malformed_rows: usize,
}

pub fn run_linux_event_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<LinuxEventDetectionReport> {
    if !resolved.host_events_enabled() {
        return Ok(LinuxEventDetectionReport::default());
    }
    let (events, malformed_rows) = read_linux_events(&layout.linux_events)?;
    logger.log(format!(
        "detector: Linux host events has {} row(s), {} malformed row(s)",
        events.len(),
        malformed_rows
    ))?;

    let mut findings = Vec::new();
    for event in &events {
        if let Some(finding) = finding_from_linux_event(event, findings.len() + 1) {
            findings.push(finding);
        }
    }
    findings.extend(ssh_brute_force_findings(&events));
    Ok(LinuxEventDetectionReport {
        findings,
        rows_seen: events.len(),
        malformed_rows,
    })
}

/// SSH/auth 爆破聚合：同一源 IP 10 分钟内失败登录 ≥5 次；失败窗口内
/// （首个失败起算 WINDOW_MS）随后成功则升分。
/// 覆盖 auth.log 的 "Failed password" / auditd USER_AUTH 失败等已规范化事件。
/// 时间缺失/不可解析的记录不参与窗口聚合计数（防膨胀），单独计数写入说明。
fn ssh_brute_force_findings(events: &[LinuxEvent]) -> Vec<Finding> {
    const WINDOW_MS: i64 = 10 * 60 * 1000;
    const FAIL_THRESHOLD: usize = 5;
    let mut findings = Vec::new();
    let mut by_ip: std::collections::BTreeMap<String, TimedAttempts> =
        std::collections::BTreeMap::new();
    for event in events {
        let Some(action) = event.action.as_deref() else {
            continue;
        };
        if action != "login_failed" && action != "login_success" {
            continue;
        }
        let ip = event.src_ip.clone().unwrap_or_default();
        if ip.is_empty() || ip == "-" {
            continue;
        }
        let millis = parse_timestamp_millis(event.timestamp.as_deref());
        let failed = action == "login_failed";
        let attempts = by_ip.entry(ip).or_default();
        match millis {
            Some(millis) => attempts.timed.push((millis, failed)),
            None => {
                if failed {
                    attempts.untimed_failures += 1;
                }
            }
        }
    }
    for (ip, timed_attempts) in by_ip {
        let mut attempts = timed_attempts.timed;
        attempts.sort_by_key(|(millis, _)| *millis);
        let mut window_start = 0usize;
        let mut index = 0usize;
        while index < attempts.len() {
            while window_start < index
                && attempts[index].0.saturating_sub(attempts[window_start].0) > WINDOW_MS
            {
                window_start += 1;
            }
            let failures = attempts[window_start..=index]
                .iter()
                .filter(|(_, failed)| *failed)
                .count();
            if failures >= FAIL_THRESHOLD {
                // 成功登录必须落在失败窗口内（首个失败起算 WINDOW_MS）才加分。
                let first_failure_millis = attempts[window_start..=index]
                    .iter()
                    .filter(|(_, failed)| *failed)
                    .map(|(millis, _)| *millis)
                    .min();
                let later_success = first_failure_millis.is_some_and(|first_failure| {
                    attempts.iter().any(|(millis, failed)| {
                        !failed
                            && *millis >= first_failure
                            && millis.saturating_sub(first_failure) <= WINDOW_MS
                    })
                });
                let score = if later_success { 80 } else { 60 };
                let sample = events.iter().find(|event| {
                    event.src_ip.as_deref() == Some(ip.as_str())
                        && event.action.as_deref().is_some_and(|action| {
                            action == "login_failed" || action == "login_success"
                        })
                });
                let Some(event) = sample else {
                    continue;
                };
                let mut untimed_note = String::new();
                if timed_attempts.untimed_failures > 0 {
                    untimed_note = format!(
                        " {} further failed login(s) from this source lacked a parseable timestamp and were excluded from the 10-minute window count.",
                        timed_attempts.untimed_failures
                    );
                }
                let mut finding = build_finding(
                    0,
                    event,
                    score,
                    "brute_force",
                    "HOST-LINUX-SSHBRUTE-001",
                    "Repeated SSH/auth failures from one source",
                    format!(
                        "Source {ip} produced {failures} failed login(s) within 10 minutes{}{}. Treat as brute-force evidence for manual review, not proof of compromise.",
                        if later_success { ", followed by a successful login" } else { "" },
                        untimed_note
                    ),
                );
                finding.finding_id = format!("HE-LNX-BF-{ip}");
                findings.push(finding);
                break;
            }
            index += 1;
        }
    }
    findings
}

/// 同一源 IP 的登录尝试：有时间戳的参与窗口聚合，无时间的单独计数。
#[derive(Default)]
struct TimedAttempts {
    timed: Vec<(i64, bool)>,
    untimed_failures: usize,
}

/// RFC3339/常用时间串 → 毫秒；缺失或解析失败返回 None
/// （无时间数据不参与窗口聚合，防止计数膨胀）。
fn parse_timestamp_millis(value: Option<&str>) -> Option<i64> {
    let value = value?;
    crate::time_utils::parse_datetime(value)
        .ok()
        .map(|dt| (dt.unix_timestamp_nanos() / 1_000_000) as i64)
}

fn finding_from_linux_event(event: &LinuxEvent, index: usize) -> Option<Finding> {
    let user = event.user.as_deref().unwrap_or_default();
    let command = event.command_line_summary.as_deref().unwrap_or_default();
    let process = event.process_name.as_deref().unwrap_or_default();
    let action = event.action.as_deref().unwrap_or_default();

    if matches!(action, "execve" | "sudo" | "syscall")
        && is_web_user(user, event.uid.as_deref())
        && suspicious_execution(process, command, event.object_path.as_deref())
    {
        return Some(build_finding(
            index,
            event,
            80,
            RULE_CATEGORY,
            "HOST-LINUX-EXECUTION-001",
            "Linux Web-facing user executed suspicious command",
            format!(
                "Linux host event recorded user `{}` executing `{}` with command `{}`. Treat as suspicious host-event evidence, not proof of compromise.",
                display_or(user, event.uid.as_deref().unwrap_or("unknown user")),
                display_or(process, "unknown process"),
                display_or(command, event.object_path.as_deref().unwrap_or("n/a"))
            ),
        ));
    }
    if matches!(action, "service_started" | "service_failed")
        && suspicious_persistence_path(event.object_path.as_deref().or(event.unit.as_deref()))
    {
        return Some(build_finding(
            index,
            event,
            66,
            "persistence_service",
            "HOST-LINUX-PERSISTENCE-001",
            "Linux systemd service references unusual path or unit",
            format!(
                "Linux service event recorded unit `{}` message `{}`. Treat as suspicious persistence evidence, not proof of compromise.",
                display_or(event.unit.as_deref().unwrap_or_default(), "unknown unit"),
                display_or(event.object_path.as_deref().unwrap_or_default(), "n/a")
            ),
        ));
    }
    if action == "cron" && suspicious_execution(process, command, event.object_path.as_deref()) {
        return Some(build_finding(
            index,
            event,
            64,
            "persistence_service",
            "HOST-LINUX-CRON-001",
            "Linux cron event contains suspicious command",
            format!(
                "Linux cron event recorded command `{}`. Treat as suspicious scheduled execution evidence, not proof of compromise.",
                display_or(command, event.object_path.as_deref().unwrap_or("n/a"))
            ),
        ));
    }
    None
}

fn build_finding(
    index: usize,
    event: &LinuxEvent,
    score: u16,
    category: &str,
    rule_id: &str,
    rule_name: &str,
    evidence_summary: String,
) -> Finding {
    // 评分拆分只在专用字段记一次（host_event_score），不再 from_base 同值双记。
    let mut breakdown = ScoreBreakdown::default();
    breakdown.host_event_score = score as i16;
    Finding {
        finding_id: format!("HE-LNX-F-{index:06}"),
        timestamp: event.timestamp.clone(),
        severity: Severity::from_score(score),
        score,
        confidence: crate::model::confidence_for(score, EvidenceQuality::Q1),
        evidence_quality: EvidenceQuality::Q1,
        evidence_quality_basis:
            "Q1 direct host event evidence from supplied Linux audit/auth/journald export".to_string(),
        score_breakdown: breakdown,
        category: category.to_string(),
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        source_type: "linux_event".to_string(),
        source_file: Some(event.source_file.clone()),
        line_number: Some(event.line_number),
        remote_ip: event.src_ip.clone(),
        method: None,
        uri_path: None,
        status: None,
        evidence_summary,
        raw_hash: Some(event.raw_hash.clone()),
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: "Review adjacent Web/application logs, process ancestry, user ownership, and persistence state before drawing conclusions.".to_string(),
    }
}

/// 读入 Linux 事件 jsonl，返回 (事件, 坏行数)。坏行计数并跳过，不再静默丢弃。
fn read_linux_events(path: &std::path::Path) -> Result<(Vec<LinuxEvent>, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut malformed = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LinuxEvent>(&line) {
            Ok(event) => events.push(event),
            Err(_) => malformed += 1,
        }
    }
    Ok((events, malformed))
}

fn is_web_user(user: &str, uid: Option<&str>) -> bool {
    let lower = user.to_ascii_lowercase();
    [
        "www-data", "apache", "nginx", "httpd", "tomcat", "jboss", "wildfly", "php-fpm",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || matches!(uid, Some("33" | "48"))
}

fn suspicious_execution(process: &str, command: &str, object_path: Option<&str>) -> bool {
    let combined = format!(
        "{} {} {}",
        process,
        command,
        object_path.unwrap_or_default()
    )
    .to_ascii_lowercase();
    [
        "/bin/sh",
        " bash",
        "dash",
        "curl",
        "wget",
        "python",
        "perl",
        "php ",
        "gcc",
        " chmod ",
        "nc ",
        "netcat",
        "socat",
        "/dev/tcp/",
        "|sh",
        "| sh",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

fn suspicious_persistence_path(path: Option<&str>) -> bool {
    let lower = path.unwrap_or_default().to_ascii_lowercase();
    [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/var/www/",
        "/usr/share/nginx/html",
        "curl",
        "wget",
        "python",
        "bash",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str, ip: &str, timestamp: Option<&str>) -> LinuxEvent {
        LinuxEvent {
            event_id: "1".to_string(),
            timestamp: timestamp.map(str::to_string),
            source: None,
            unit: None,
            user: None,
            uid: None,
            pid: None,
            ppid: None,
            process_name: None,
            command_line_summary: None,
            cwd: None,
            src_ip: Some(ip.to_string()),
            tty: None,
            session: None,
            action: Some(action.to_string()),
            object_path: None,
            result: None,
            raw_hash: "hash".to_string(),
            parser_confidence: 1.0,
            source_file: "fixture".to_string(),
            line_number: 1,
        }
    }

    #[test]
    fn ssh_brute_force_ignores_untimestamped_attempts_for_window_count() {
        // 4 次有时间的失败 + 10 次无时间的失败：窗口计数不膨胀，不触发。
        let mut events = Vec::new();
        for second in 0..4u64 {
            events.push(event(
                "login_failed",
                "203.0.113.9",
                Some(&format!("2026-05-15T08:00:{second:02}Z")),
            ));
        }
        for _ in 0..10 {
            events.push(event("login_failed", "203.0.113.9", None));
        }
        assert!(ssh_brute_force_findings(&events).is_empty());

        // 补齐第 5 次有时间的失败后触发，并说明被排除的无时间失败。
        events.push(event(
            "login_failed",
            "203.0.113.9",
            Some("2026-05-15T08:00:30Z"),
        ));
        let findings = ssh_brute_force_findings(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence_summary
            .contains("lacked a parseable timestamp"));
    }

    #[test]
    fn ssh_brute_force_later_success_must_be_inside_failure_window() {
        let mut events = Vec::new();
        for second in 0..5u64 {
            events.push(event(
                "login_failed",
                "203.0.113.9",
                Some(&format!("2026-05-15T08:00:{second:02}Z")),
            ));
        }
        events.push(event(
            "login_success",
            "203.0.113.9",
            Some("2026-05-15T23:00:00Z"),
        ));
        let findings = ssh_brute_force_findings(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].score, 60);
    }
}
