use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::correlation::{AttackChain, CorrelationReport};
use crate::error::Result;
use crate::model::Finding;
use crate::output::paths::OutputLayout;
use crate::output::writers;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEvent {
    pub event_id: String,
    pub timestamp: Option<String>,
    pub source_type: TimelineSourceType,
    pub severity: Option<crate::model::Severity>,
    pub subject: Option<String>,
    pub action: String,
    pub object: Option<String>,
    pub source_file: Option<String>,
    pub line_number: Option<u64>,
    pub related_finding_ids: Vec<String>,
    pub confidence: f32,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineSourceType {
    Http,
    Database,
    Waf,
    AppLog,
    File,
    Process,
    Network,
    Auth,
    Persistence,
    Yara,
    Ioc,
    Error,
}

impl TimelineSourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Database => "database",
            Self::Waf => "waf",
            Self::AppLog => "app_log",
            Self::File => "file",
            Self::Process => "process",
            Self::Network => "network",
            Self::Auth => "auth",
            Self::Persistence => "persistence",
            Self::Yara => "yara",
            Self::Ioc => "ioc",
            Self::Error => "error",
        }
    }
}

pub fn initialize_empty_timeline(layout: &OutputLayout) -> Result<()> {
    writers::write_text(&layout.timeline_jsonl, "")?;
    write_timeline_csv_header(&layout.timeline_csv)?;
    write_attack_chains_markdown(&layout.attack_chains, &[])
}

pub fn write_timeline_outputs(
    layout: &OutputLayout,
    findings: &[Finding],
    _correlation: &CorrelationReport,
) -> Result<Vec<TimelineEvent>> {
    let mut events = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| event_from_finding(index + 1, finding))
        .collect::<Vec<_>>();
    events.sort_by_key(timeline_sort_key);

    write_timeline_jsonl(&layout.timeline_jsonl, &events)?;
    write_timeline_csv(&layout.timeline_csv, &events)?;
    Ok(events)
}

fn write_timeline_csv_header(path: &Path) -> Result<()> {
    writers::write_text(
        path,
        "event_id,timestamp,source_type,severity,subject,action,object,source_file,line_number,related_finding_ids,confidence,summary\n",
    )
}

fn event_from_finding(index: usize, finding: &Finding) -> TimelineEvent {
    TimelineEvent {
        event_id: format!("TL-{index:06}"),
        timestamp: finding.timestamp.clone(),
        source_type: source_type_from_finding(finding),
        severity: Some(finding.severity),
        subject: finding.remote_ip.clone(),
        action: action_from_finding(finding),
        object: finding
            .uri_path
            .clone()
            .or_else(|| finding.source_file.clone()),
        source_file: finding.source_file.clone(),
        line_number: finding.line_number,
        related_finding_ids: related_ids_for_timeline(finding),
        confidence: confidence_from_score(finding.score),
        summary: timeline_summary(finding),
    }
}

fn source_type_from_finding(finding: &Finding) -> TimelineSourceType {
    match finding.source_type.as_str() {
        "access_log" => TimelineSourceType::Http,
        "db_log" => TimelineSourceType::Database,
        // WAF/应用日志有自己的证据语义,不再笼统映射为 Error;
        // action 列(waf_event/application_error)可进一步区分行为。
        "app_log" => TimelineSourceType::AppLog,
        "waf_log" => TimelineSourceType::Waf,
        "file" => {
            if finding.category == "yara_match" {
                TimelineSourceType::Yara
            } else {
                TimelineSourceType::File
            }
        }
        "process" => TimelineSourceType::Process,
        "network" => TimelineSourceType::Network,
        "account" | "logon" => TimelineSourceType::Auth,
        "persistence" => TimelineSourceType::Persistence,
        "ioc" => TimelineSourceType::Ioc,
        _ => TimelineSourceType::Error,
    }
}

fn action_from_finding(finding: &Finding) -> String {
    match finding.source_type.as_str() {
        "access_log" => finding
            .method
            .clone()
            .unwrap_or_else(|| "http_request".to_string()),
        "db_log" => "database_event".to_string(),
        "app_log" => "application_error".to_string(),
        "waf_log" => "waf_event".to_string(),
        "file" => "file_evidence".to_string(),
        "process" => "process_evidence".to_string(),
        "network" => "network_evidence".to_string(),
        "persistence" => "persistence_evidence".to_string(),
        "ioc" => "ioc_match".to_string(),
        _ => "evidence".to_string(),
    }
}

fn related_ids_for_timeline(finding: &Finding) -> Vec<String> {
    let mut ids = BTreeSet::new();
    ids.insert(finding.finding_id.clone());
    ids.extend(finding.related_ids.iter().cloned());
    ids.into_iter().collect()
}

fn confidence_from_score(score: u16) -> f32 {
    (f32::from(score.min(100)) / 100.0 * 100.0).round() / 100.0
}

fn timeline_summary(finding: &Finding) -> String {
    let level = finding.evidence_chain_level.as_deref().unwrap_or("L1");
    format!(
        "{level} {} {} score {}: {}",
        finding.source_type, finding.rule_id, finding.score, finding.evidence_summary
    )
}

fn timeline_sort_key(event: &TimelineEvent) -> ((u8, i128), u8, String) {
    (
        timestamp_sort_instant(event.timestamp.as_deref()),
        source_sort_rank(event.source_type),
        event.event_id.clone(),
    )
}

/// Some(nanos)→(0, nanos),无/不可解析→(1, 0):None 恒排最后,
/// 等价于旧 "9999" 哨兵语义,但混合时区偏移(+08:00 与 Z)时仍按真实时刻排序。
fn timestamp_sort_instant(timestamp: Option<&str>) -> (u8, i128) {
    match crate::time_utils::timestamp_instant_nanos(timestamp) {
        Some(nanos) => (0, nanos),
        None => (1, 0),
    }
}

fn source_sort_rank(source_type: TimelineSourceType) -> u8 {
    match source_type {
        TimelineSourceType::Http => 10,
        TimelineSourceType::Database => 20,
        TimelineSourceType::Waf => 22,
        TimelineSourceType::AppLog => 24,
        TimelineSourceType::Error => 25,
        TimelineSourceType::File => 30,
        TimelineSourceType::Yara => 35,
        TimelineSourceType::Process => 40,
        TimelineSourceType::Network => 50,
        TimelineSourceType::Persistence => 60,
        TimelineSourceType::Auth => 70,
        TimelineSourceType::Ioc => 80,
    }
}

fn write_timeline_jsonl(path: &Path, rows: &[TimelineEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

fn write_timeline_csv(path: &Path, rows: &[TimelineEvent]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "event_id",
        "timestamp",
        "source_type",
        "severity",
        "subject",
        "action",
        "object",
        "source_file",
        "line_number",
        "related_finding_ids",
        "confidence",
        "summary",
    ])?;
    for row in rows {
        writer.write_record([
            row.event_id.as_str(),
            row.timestamp.as_deref().unwrap_or_default(),
            row.source_type.as_str(),
            row.severity
                .map(|severity| severity.as_str())
                .unwrap_or_default(),
            row.subject.as_deref().unwrap_or_default(),
            row.action.as_str(),
            row.object.as_deref().unwrap_or_default(),
            row.source_file.as_deref().unwrap_or_default(),
            &row.line_number
                .map(|line| line.to_string())
                .unwrap_or_default(),
            &row.related_finding_ids.join(";"),
            &format!("{:.2}", row.confidence),
            row.summary.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_attack_chains_markdown(path: &Path, rows: &[AttackChain]) -> Result<()> {
    let mut report = String::new();
    report.push_str("# dumpall Attack Chains\n\n");
    report.push_str("These chains are suspicious evidence groupings for manual review, not proof of compromise.\n\n");
    if rows.is_empty() {
        report.push_str("No multi-evidence attack chains were produced.\n");
        return writers::write_text(path, &report);
    }

    for chain in rows.iter().take(20) {
        report.push_str(&format!(
            "## {} {}\n\n",
            chain.chain_id, chain.evidence_chain_level
        ));
        report.push_str(&format!("- Severity: {}\n", chain.highest_severity));
        report.push_str(&format!("- Max score: {}\n", chain.max_score));
        report.push_str(&format!(
            "- Window: {} to {}\n",
            display_or(&chain.first_seen, "unknown"),
            display_or(&chain.last_seen, "unknown")
        ));
        report.push_str(&format!(
            "- Source IPs: {}\n",
            display_or(&chain.remote_ips, "n/a")
        ));
        report.push_str(&format!("- Paths: {}\n", display_or(&chain.paths, "n/a")));
        report.push_str(&format!(
            "- Categories: {}\n",
            display_or(&chain.categories, "n/a")
        ));
        report.push_str(&format!("- Findings: {}\n", chain.finding_ids.join(", ")));
        report.push_str(&format!("- Basis: {}\n", chain.evidence_chain_basis));
        report.push_str(&format!("- Sequence: {}\n\n", chain.summary));
    }

    writers::write_text(path, &report)
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_event_serializes_as_json() {
        let event = TimelineEvent {
            event_id: "evt-1".to_string(),
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            source_type: TimelineSourceType::Http,
            severity: Some(crate::model::Severity::High),
            subject: Some("192.0.2.10".to_string()),
            action: "requested".to_string(),
            object: Some("/login".to_string()),
            source_file: Some("access.log".to_string()),
            line_number: Some(42),
            related_finding_ids: vec!["finding-1".to_string()],
            confidence: 0.8,
            summary: "HTTP request linked to suspicious evidence".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""source_type":"http""#));
        assert!(json.contains(r#""severity":"high""#));
    }

    #[test]
    fn source_type_uses_dedicated_waf_and_applog_variants() {
        let waf = test_event_with_source("waf_log");
        assert_eq!(waf.source_type, TimelineSourceType::Waf);
        assert_eq!(waf.source_type.as_str(), "waf");
        assert_eq!(waf.action, "waf_event");

        let app = test_event_with_source("app_log");
        assert_eq!(app.source_type, TimelineSourceType::AppLog);
        assert_eq!(app.source_type.as_str(), "app_log");
        assert_eq!(app.action, "application_error");
    }

    #[test]
    fn sort_key_orders_mixed_offsets_and_missing_last() {
        // 05:00Z 早于 21:00+08:00(=13:00Z);ISO 字符串字典序会得出相反顺序。
        let early = TimelineEvent {
            event_id: "TL-1".to_string(),
            timestamp: Some("2026-08-27T05:00:00Z".to_string()),
            source_type: TimelineSourceType::Http,
            severity: None,
            subject: None,
            action: "GET".to_string(),
            object: None,
            source_file: None,
            line_number: None,
            related_finding_ids: Vec::new(),
            confidence: 0.5,
            summary: String::new(),
        };
        let late = TimelineEvent {
            event_id: "TL-2".to_string(),
            timestamp: Some("2026-08-27T21:00:00+08:00".to_string()),
            ..early.clone()
        };
        let undated = TimelineEvent {
            event_id: "TL-3".to_string(),
            timestamp: None,
            ..early.clone()
        };
        let unparseable = TimelineEvent {
            event_id: "TL-4".to_string(),
            timestamp: Some("not-a-timestamp".to_string()),
            ..early.clone()
        };
        assert!(timeline_sort_key(&early) < timeline_sort_key(&late));
        assert!(timeline_sort_key(&late) < timeline_sort_key(&undated));
        // 无时间与不可解析同桶（时间分量相同,由 event_id 决胜）。
        assert_eq!(timeline_sort_key(&undated).0, timeline_sort_key(&unparseable).0);

        let mut events = vec![late.clone(), undated.clone(), early.clone()];
        events.sort_by_key(timeline_sort_key);
        assert_eq!(
            events.iter().map(|event| event.event_id.clone()).collect::<Vec<_>>(),
            vec!["TL-1", "TL-2", "TL-3"]
        );
    }

    fn test_event_with_source(source_type: &str) -> TimelineEvent {
        event_from_finding(
            1,
            &crate::model::Finding {
                finding_id: "F-1".to_string(),
                timestamp: Some("2026-08-27T08:00:00Z".to_string()),
                severity: crate::model::Severity::Medium,
                score: 50,
                confidence: crate::model::Confidence::Medium,
                evidence_quality: crate::model::EvidenceQuality::Q2,
                evidence_quality_basis: String::new(),
                score_breakdown: crate::model::ScoreBreakdown::from_final_score(50),
                category: "test".to_string(),
                rule_id: "R-1".to_string(),
                rule_name: "rule".to_string(),
                source_type: source_type.to_string(),
                source_file: None,
                line_number: None,
                remote_ip: None,
                method: None,
                uri_path: None,
                status: None,
                evidence_summary: String::new(),
                raw_hash: None,
                related_ids: Vec::new(),
                evidence_chain_level: None,
                evidence_chain_basis: None,
                recommendation: String::new(),
            },
        )
    }
}
