use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{EvidenceQuality, Finding, ScoreBreakdown, Severity, WindowsEvent};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};
use crate::report::zh;

pub const RULE_CATEGORY: &str = "host_windows_execution";

#[derive(Debug, Default)]
pub struct HostEventDetectionReport {
    pub findings: Vec<Finding>,
    pub rows_seen: usize,
    /// 事件 jsonl 中无法反序列化的坏行数（跳过但计数，不再静默丢弃）。
    pub malformed_rows: usize,
}

pub fn run_windows_event_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<HostEventDetectionReport> {
    if !resolved.host_events_enabled() {
        return Ok(HostEventDetectionReport::default());
    }
    let (events, malformed_rows) = read_windows_events(&layout.windows_events)?;
    logger.log(format!(
        "detector: Windows host events has {} row(s), {} malformed row(s)",
        events.len(),
        malformed_rows
    ))?;

    let mut findings = Vec::new();
    for event in &events {
        if let Some(finding) = finding_from_windows_event(event, findings.len() + 1) {
            findings.push(finding);
        }
    }
    findings.extend(brute_force_findings(&events));
    findings.extend(remote_logon_findings(&events));
    Ok(HostEventDetectionReport {
        findings,
        rows_seen: events.len(),
        malformed_rows,
    })
}

/// 4625 暴力破解聚合：同一源 IP 在 10 分钟内失败 ≥5 次；若失败窗口内
/// （首个失败起算 WINDOW_MS）出现同 IP 4624 成功，分数上调并升级摘要
/// （爆破后成功登录是最高信号之一）。
/// 时间缺失/不可解析的记录不参与窗口聚合计数（防止无时间数据膨胀计数），
/// 但按 IP 单独计数并在 evidence_summary 说明。
fn brute_force_findings(events: &[WindowsEvent]) -> Vec<Finding> {
    const WINDOW_MS: i64 = 10 * 60 * 1000;
    const FAIL_THRESHOLD: usize = 5;
    let mut findings = Vec::new();
    // (ip, [(毫秒时间戳, 是否失败)])；无时间的尝试单独统计。
    let mut by_ip: std::collections::BTreeMap<String, TimedAttempts> =
        std::collections::BTreeMap::new();
    for event in events {
        let Some(action) = event.action.as_deref() else {
            continue;
        };
        if action != "logon_failure" && action != "logon_success" {
            continue;
        }
        let ip = event.source_ip.clone().unwrap_or_default();
        if ip.is_empty() || ip == "-" {
            continue;
        }
        let millis = parse_timestamp_millis(event.timestamp.as_deref());
        let failed = action == "logon_failure";
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
                let score = if later_success { 82 } else { 62 };
                let sample = attempts.iter().find_map(|(millis, failed)| {
                    events.iter().find(|event| {
                        event.source_ip.as_deref() == Some(ip.as_str())
                            && event.action.as_deref()
                                == Some(if *failed {
                                    "logon_failure"
                                } else {
                                    "logon_success"
                                })
                            && parse_timestamp_millis(event.timestamp.as_deref()) == Some(*millis)
                    })
                });
                let mut untimed_note = String::new();
                if timed_attempts.untimed_failures > 0 {
                    untimed_note = format!(
                        " {} further failed logon(s) from this source lacked a parseable timestamp and were excluded from the 10-minute window count.",
                        timed_attempts.untimed_failures
                    );
                }
                let mut finding = if let Some(event) = sample {
                    build_finding(
                        0,
                        event,
                        score,
                        "brute_force",
                        "HOST-WINDOWS-BRUTE-001",
                        "Repeated Windows logon failures from one source",
                        format!(
                            "Source {ip} produced {failures} failed logon(s) (4625) within 10 minutes{}{}. Treat as brute-force evidence for manual review, not proof of compromise.",
                            if later_success { ", followed by a successful logon (4624)" } else { "" },
                            untimed_note
                        ),
                    )
                } else {
                    continue;
                };
                finding.finding_id = format!("HE-WIN-BF-{ip}");
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

/// 4624 网络型登录（类型 3/10 经 IpAddress 体现）且源地址为公网：
/// 服务器场景下公网源的成功远程登录值得人工确认。
fn remote_logon_findings(events: &[WindowsEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for event in events {
        if event.action.as_deref() != Some("logon_success") {
            continue;
        }
        let Some(ip) = event.source_ip.as_deref() else {
            continue;
        };
        if ip.is_empty() || ip == "-" || !is_public_ip(ip) {
            continue;
        }
        findings.push(build_finding(
            findings.len() + 1,
            event,
            58,
            "anomalous_login",
            "HOST-WIN-REMOTE-LOGON-001",
            "Successful network logon from public address",
            format!(
                "Windows 4624 successful logon for user `{}` from public source {ip}. Confirm this access is expected; treat as lead, not proof of compromise.",
                event.target_user.as_deref().or(event.user.as_deref()).unwrap_or("unknown")
            ),
        ));
    }
    findings
}

/// RFC1918/回环/链路本地/ULA 以外的地址视为公网。
/// IPv6 补充：fe80::/10 链路本地、fc00::/7 ULA；v4-mapped（::ffff:x.x.x.x）
/// 归一为 v4 后按 v4 内网口径判断；::1 回环由 is_loopback 覆盖。
fn is_public_ip(value: &str) -> bool {
    let Ok(address) = value.parse::<std::net::IpAddr>() else {
        return false;
    };
    match address {
        std::net::IpAddr::V4(v4) => is_public_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                // v4-mapped v6：折算回 v4 按内网口径判断。
                let v4 = std::net::Ipv4Addr::from(
                    ((segments[6] as u32) << 16) | segments[7] as u32,
                );
                return is_public_ipv4(v4);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fe80::/10 链路本地。
                || (segments[0] & 0xffc0) == 0xfe80
                // fc00::/7 唯一本地（ULA）。
                || (segments[0] & 0xfe00) == 0xfc00)
        }
    }
}

fn is_public_ipv4(v4: std::net::Ipv4Addr) -> bool {
    !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast())
}

/// RFC3339/常用时间串 → 毫秒；缺失或解析失败返回 None
/// （无时间数据不参与窗口聚合，防止计数膨胀）。
fn parse_timestamp_millis(value: Option<&str>) -> Option<i64> {
    let value = value?;
    crate::time_utils::parse_datetime(value)
        .ok()
        .map(|dt| dt.unix_timestamp_nanos() as i64 / 1_000_000)
}

pub fn write_host_events_report(
    path: &Path,
    windows_rows: usize,
    linux_rows: usize,
    findings: &[Finding],
) -> Result<()> {
    let mut report = String::new();
    report.push_str("# 主机事件报告\n\n");
    report.push_str("- 事件采集基于用户提供的离线导出文件和本地文本日志。\n");
    report.push_str("- 二进制 EVTX 和二进制 journald 输入不会被伪解析；如未先导出为 XML/JSON/文本，将记录为证据缺口。\n");
    report.push_str(&format!("- Windows 事件行数：{windows_rows}\n"));
    report.push_str(&format!("- Linux 事件行数：{linux_rows}\n"));
    report.push_str(&format!("- 主机事件发现数：{}\n\n", findings.len()));
    report.push_str("## 发现摘要\n\n");
    if findings.is_empty() {
        report.push_str("未产生主机事件发现。\n");
    } else {
        for finding in findings.iter().take(30) {
            report.push_str(&format!(
                "- [{}] {} 分数 {} 证据质量 {} 来源 {}\n",
                zh::severity_label(finding.severity.as_str()),
                finding.rule_id,
                finding.score,
                zh::evidence_quality_label(finding.evidence_quality.as_str()),
                finding.source_file.as_deref().unwrap_or("无数据")
            ));
        }
    }
    writers::write_text(path, &report)
}

fn finding_from_windows_event(event: &WindowsEvent, index: usize) -> Option<Finding> {
    let code = event.event_code.as_deref().unwrap_or_default();
    let parent = event.parent_process_name.as_deref().unwrap_or_default();
    let process = event.process_name.as_deref().unwrap_or_default();
    let command = event.command_line_summary.as_deref().unwrap_or_default();
    let action = event.action.as_deref().unwrap_or_default();

    if code == "4688" && is_web_parent(parent) && suspicious_command(process, command) {
        return Some(build_finding(
            index,
            event,
            78,
            RULE_CATEGORY,
            "HOST-WINDOWS-EXECUTION-001",
            "Windows Web-facing process spawned suspicious command",
            format!(
                "Windows event 4688 recorded parent `{}` spawning `{}` with command `{}`. Treat as suspicious host-event evidence, not proof of compromise.",
                display_or(parent, "unknown parent"),
                display_or(process, "unknown process"),
                display_or(command, "n/a")
            ),
        ));
    }
    if is_powershell_event(event) && suspicious_powershell(command) {
        return Some(build_finding(
            index,
            event,
            74,
            RULE_CATEGORY,
            "HOST-WINDOWS-POWERSHELL-001",
            "Windows PowerShell event with suspicious script content",
            format!(
                "Windows PowerShell event {} recorded suspicious script or command content `{}`. Treat as suspicious host-event evidence, not proof of compromise.",
                display_or(code, "unknown"),
                display_or(command, "n/a")
            ),
        ));
    }
    if action == "service_install" && suspicious_persistence_path(event.object_path.as_deref()) {
        return Some(build_finding(
            index,
            event,
            68,
            "persistence_service",
            "HOST-WINDOWS-SERVICE-001",
            "Windows service installation uses unusual path",
            format!(
                "Windows service event recorded service `{}` path `{}`. Treat as suspicious persistence evidence, not proof of compromise.",
                display_or(event.service_name.as_deref().unwrap_or_default(), "unknown service"),
                display_or(event.object_path.as_deref().unwrap_or_default(), "n/a")
            ),
        ));
    }
    if matches!(action, "scheduled_task_create" | "scheduled_task_update")
        && (suspicious_command(process, command)
            || suspicious_persistence_path(event.object_path.as_deref()))
    {
        return Some(build_finding(
            index,
            event,
            66,
            "persistence_service",
            "HOST-WINDOWS-TASK-001",
            "Windows scheduled task uses suspicious command or path",
            format!(
                "Windows scheduled task event recorded task `{}` command `{}`. Treat as suspicious persistence evidence, not proof of compromise.",
                display_or(event.task_name.as_deref().unwrap_or_default(), "unknown task"),
                display_or(command, event.object_path.as_deref().unwrap_or("n/a"))
            ),
        ));
    }
    if action == "log_clear" {
        // 仅 System/Security 通道的清日志（1102/104）构成反取证信号；
        // 诊断类通道（如 Diagnosis-Scripted/Operational）的 104 是其日常
        // 自清行为，实机上会产生大量误报；channel 缺失时证据不足，不触发。
        let channel = event.channel.as_deref().unwrap_or_default();
        let is_core_channel =
            channel.eq_ignore_ascii_case("Security") || channel.eq_ignore_ascii_case("System");
        if is_core_channel {
            return Some(build_finding(
                index,
                event,
                62,
                "host_windows_log_clear",
                "HOST-WINDOWS-LOGCLEAR-001",
                "Windows security log was cleared",
                "Windows event 1102 recorded log clearing. Treat as suspicious anti-forensics evidence requiring operator review, not proof of compromise.".to_string(),
            ));
        }
        return None;
    }
    None
}

fn build_finding(
    index: usize,
    event: &WindowsEvent,
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
        finding_id: format!("HE-WIN-F-{index:06}"),
        timestamp: event.timestamp.clone(),
        severity: Severity::from_score(score),
        score,
        confidence: crate::model::confidence_for(score, EvidenceQuality::Q1),
        evidence_quality: EvidenceQuality::Q1,
        evidence_quality_basis:
            "Q1 direct host event evidence from supplied Windows event export".to_string(),
        score_breakdown: breakdown,
        category: category.to_string(),
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        source_type: "windows_event".to_string(),
        source_file: Some(event.source_file.clone()),
        line_number: Some(event.line_number),
        remote_ip: event.source_ip.clone(),
        method: None,
        uri_path: None,
        status: None,
        evidence_summary,
        raw_hash: Some(event.raw_hash.clone()),
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: "Review the adjacent Web, process, service, and authentication evidence; validate parent process lineage and change history before drawing conclusions.".to_string(),
    }
}

/// 读入 Windows 事件 jsonl，返回 (事件, 坏行数)。坏行计数并跳过，不再静默丢弃。
fn read_windows_events(path: &Path) -> Result<(Vec<WindowsEvent>, usize)> {
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
        match serde_json::from_str::<WindowsEvent>(&line) {
            Ok(event) => events.push(event),
            Err(_) => malformed += 1,
        }
    }
    Ok((events, malformed))
}

fn is_web_parent(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "w3wp.exe",
        "httpd",
        "apache",
        "nginx",
        "tomcat",
        "java.exe",
        "php-cgi",
        "php-fpm",
        "node.exe",
        "dotnet.exe",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn suspicious_command(process: &str, command: &str) -> bool {
    let combined = format!("{process} {command}").to_ascii_lowercase();
    [
        "powershell",
        "cmd.exe",
        "certutil",
        "bitsadmin",
        "curl",
        "wget",
        "rundll32",
        "regsvr32",
        "mshta",
        "bash",
        "\\sh.exe",
        " -enc",
        "frombase64string",
        "downloadstring",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

fn suspicious_powershell(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    [
        "-enc",
        "encodedcommand",
        "frombase64string",
        "downloadstring",
        "iex",
        "invoke-expression",
        "webclient",
        "bypass",
        "hidden",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn suspicious_persistence_path(path: Option<&str>) -> bool {
    let lower = path.unwrap_or_default().to_ascii_lowercase();
    [
        "\\temp\\",
        "\\tmp\\",
        "\\users\\public\\",
        "\\programdata\\",
        "\\inetpub\\",
        "app_data",
        ".ps1",
        ".vbs",
        ".js",
        "powershell",
        "cmd.exe",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_powershell_event(event: &WindowsEvent) -> bool {
    matches!(event.event_code.as_deref(), Some("4103" | "4104"))
        || event
            .provider
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("powershell")
        || event
            .process_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("powershell")
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

    #[test]
    fn is_public_ip_covers_ipv6_link_local_mapped_and_ula() {
        // IPv4 基线。
        assert!(!is_public_ip("10.1.2.3"));
        assert!(!is_public_ip("192.168.1.1"));
        assert!(is_public_ip("203.0.113.10"));
        // IPv6：回环/未指定/链路本地 fe80::/10 / ULA fc00::/7 均非公网。
        assert!(!is_public_ip("::1"));
        assert!(!is_public_ip("::"));
        assert!(!is_public_ip("fe80::1aa:2bb"));
        assert!(!is_public_ip("fd12:3456::1"));
        assert!(is_public_ip("2001:db8::1"));
        // v4-mapped：::ffff:10.x 判为内网，::ffff:203.x 判为公网。
        assert!(!is_public_ip("::ffff:10.1.2.3"));
        assert!(is_public_ip("::ffff:203.0.113.10"));
        // 非 IP 字符串不算公网源。
        assert!(!is_public_ip("not-an-ip"));
    }

    fn event(action: &str, ip: &str, timestamp: Option<&str>, channel: Option<&str>) -> WindowsEvent {
        WindowsEvent {
            event_id: "1".to_string(),
            timestamp: timestamp.map(str::to_string),
            channel: channel.map(str::to_string),
            provider: None,
            event_code: None,
            computer: None,
            user: None,
            process_name: None,
            process_id: None,
            parent_process_name: None,
            command_line_summary: None,
            source_ip: Some(ip.to_string()),
            target_user: None,
            service_name: None,
            task_name: None,
            object_path: None,
            action: Some(action.to_string()),
            result: None,
            severity: None,
            raw_hash: "hash".to_string(),
            parser_confidence: 1.0,
            source_file: "fixture".to_string(),
            line_number: 1,
        }
    }

    #[test]
    fn log_clear_requires_core_channel() {
        let with_security = event("log_clear", "-", Some("2026-05-15T08:00:00Z"), Some("Security"));
        assert!(finding_from_windows_event(&with_security, 1).is_some());
        let with_system = event("log_clear", "-", Some("2026-05-15T08:00:00Z"), Some("System"));
        assert!(finding_from_windows_event(&with_system, 1).is_some());
        // channel 缺失不再触发（空 channel 不算 Security/System）。
        let missing_channel = event("log_clear", "-", Some("2026-05-15T08:00:00Z"), None);
        assert!(finding_from_windows_event(&missing_channel, 1).is_none());
        let diagnostic = event(
            "log_clear",
            "-",
            Some("2026-05-15T08:00:00Z"),
            Some("Microsoft-Windows-Diagnosis-Scripted/Operational"),
        );
        assert!(finding_from_windows_event(&diagnostic, 1).is_none());
    }

    #[test]
    fn brute_force_later_success_must_be_inside_failure_window() {
        // 5 次失败集中在 08:00:00-08:00:40，随后 3 小时后才有成功登录：
        // 成功在失败窗口（首个失败起算 10 分钟）之外，不加分（score 62）。
        let mut events = Vec::new();
        for second in 0..5u64 {
            events.push(event(
                "logon_failure",
                "203.0.113.9",
                Some(&format!("2026-05-15T08:00:{second:02}Z")),
                None,
            ));
        }
        events.push(event(
            "logon_success",
            "203.0.113.9",
            Some("2026-05-15T11:00:00Z"),
            None,
        ));
        let findings = brute_force_findings(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].score, 62);
        assert!(!findings[0].evidence_summary.contains("followed by a successful logon"));

        // 成功发生在失败窗口内（08:02 < 08:10）则加分（score 82）。
        events.pop();
        events.push(event(
            "logon_success",
            "203.0.113.9",
            Some("2026-05-15T08:02:00Z"),
            None,
        ));
        let findings = brute_force_findings(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].score, 82);
    }

    #[test]
    fn brute_force_ignores_untimestamped_attempts_for_window_count() {
        // 4 次有时间的失败 + 10 次无时间的失败：窗口计数只算有时间的（<5 阈值），
        // 不产生时间窗聚合发现；无时间数据不膨胀计数。
        let mut events = Vec::new();
        for second in 0..4u64 {
            events.push(event(
                "logon_failure",
                "203.0.113.9",
                Some(&format!("2026-05-15T08:00:{second:02}Z")),
                None,
            ));
        }
        for _ in 0..10 {
            events.push(event("logon_failure", "203.0.113.9", None, None));
        }
        assert!(brute_force_findings(&events).is_empty());

        // 第 5 次有时间的失败补齐阈值后触发，且 evidence_summary 说明被排除的无时间失败。
        events.push(event(
            "logon_failure",
            "203.0.113.9",
            Some("2026-05-15T08:00:30Z"),
            None,
        ));
        let findings = brute_force_findings(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence_summary
            .contains("lacked a parseable timestamp"));
    }
}
