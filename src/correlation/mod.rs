use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use crate::enrich::identity::canonical_ip;
use crate::error::Result;
use crate::model::{Finding, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

const HTTP_CONTEXT_WINDOW_SECONDS: i64 = 2 * 60;
const DB_CONTEXT_WINDOW_SECONDS: i64 = 5 * 60;
const HOST_CONTEXT_WINDOW_SECONDS: i64 = 10 * 60;
const LOGIN_CONTEXT_WINDOW_SECONDS: i64 = 30 * 60;

#[derive(Debug, Clone, Default)]
pub struct CorrelationReport {
    pub relation_count: usize,
    pub high_risk_events: Vec<HighRiskEvent>,
    pub attack_ip_stats: Vec<AttackIpStat>,
    pub attack_type_stats: Vec<AttackTypeStat>,
    pub affected_url_stats: Vec<AffectedUrlStat>,
    pub suspicious_processes: Vec<Finding>,
    pub suspicious_network: Vec<Finding>,
    pub suspicious_persistence: Vec<Finding>,
    pub suspicious_app_events: Vec<Finding>,
    pub suspicious_waf_events: Vec<Finding>,
    pub recent_web_files: Vec<CsvRecord>,
    pub suspicious_files: Vec<CsvRecord>,
    pub attack_chains: Vec<AttackChain>,
}

#[derive(Debug, Clone)]
pub struct HighRiskEvent {
    pub finding_id: String,
    pub severity: String,
    pub confidence: String,
    pub evidence_quality: String,
    pub score: u16,
    pub category: String,
    pub rule_id: String,
    pub timestamp: String,
    pub remote_ip: String,
    pub uri_path: String,
    pub source_file: String,
    pub line_number: String,
    pub related_ids: String,
    pub evidence_chain_level: String,
    pub evidence_chain: String,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct AttackChain {
    pub chain_id: String,
    pub evidence_chain_level: String,
    pub evidence_chain_basis: String,
    pub max_score: u16,
    pub highest_severity: String,
    pub first_seen: String,
    pub last_seen: String,
    pub remote_ips: String,
    pub paths: String,
    pub categories: String,
    pub finding_ids: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct AttackIpStat {
    pub remote_ip: String,
    pub findings: usize,
    pub total_score: u64,
    pub max_score: u16,
    pub highest_severity: String,
    pub categories: String,
    pub top_paths: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone)]
pub struct AttackTypeStat {
    pub category: String,
    pub findings: usize,
    pub high_or_critical: usize,
    pub max_score: u16,
    pub highest_severity: String,
    pub affected_ips: String,
    pub affected_paths: String,
}

#[derive(Debug, Clone)]
pub struct AffectedUrlStat {
    pub uri_path: String,
    pub findings: usize,
    pub max_score: u16,
    pub categories: String,
    pub remote_ips: String,
}

#[derive(Debug, Clone, Default)]
pub struct CsvRecord {
    fields: BTreeMap<String, String>,
}

impl CsvRecord {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .get(&normalize_field_name(key))
            .map(String::as_str)
    }
}

#[derive(Debug, Clone)]
struct Relation {
    reason: String,
    boost_a: u16,
    boost_b: u16,
}

pub fn run_correlation(
    layout: &OutputLayout,
    findings: &mut [Finding],
    logger: &mut RunLogger,
) -> Result<CorrelationReport> {
    let recent_web_files = read_csv_records(&layout.recent_web_files)?;
    let suspicious_files = read_csv_records(&layout.suspicious_files)?;

    let mut related_ids = vec![BTreeSet::new(); findings.len()];
    let mut context_notes = vec![Vec::<String>::new(); findings.len()];
    let mut boosts = vec![0_u16; findings.len()];
    let mut relation_count = 0;

    for left in 0..findings.len() {
        for right in (left + 1)..findings.len() {
            if let Some(relation) = relation_between(&findings[left], &findings[right]) {
                relation_count += 1;
                related_ids[left].insert(findings[right].finding_id.clone());
                related_ids[right].insert(findings[left].finding_id.clone());
                context_notes[left].push(format!(
                    "{}: {}",
                    findings[right].finding_id, relation.reason
                ));
                context_notes[right].push(format!(
                    "{}: {}",
                    findings[left].finding_id, relation.reason
                ));
                boosts[left] = boosts[left].saturating_add(relation.boost_a);
                boosts[right] = boosts[right].saturating_add(relation.boost_b);
            }
        }
    }

    correlate_file_context(
        findings,
        &recent_web_files,
        &suspicious_files,
        &mut context_notes,
        &mut boosts,
    );

    for (index, finding) in findings.iter_mut().enumerate() {
        finding.related_ids = related_ids[index].iter().cloned().collect();
        let boost = boosts[index].min(30);
        if boost > 0 {
            finding.score = finding.score.saturating_add(boost).min(100);
            finding.severity = Severity::from_score(finding.score);
            finding.score_breakdown.add_correlation(boost);
            context_notes[index].push(format!(
                "correlation_score_adjustment: +{boost} based on adjacent evidence"
            ));
        }
        if !context_notes[index].is_empty() {
            append_correlation_summary(finding, &context_notes[index]);
        }
    }
    assign_evidence_chain_levels(findings, &context_notes);

    let high_risk_events = build_high_risk_events(findings, &context_notes);
    let (attack_ip_stats, skipped_placeholder_ips) = build_attack_ip_stats(findings);
    let attack_type_stats = build_attack_type_stats(findings);
    let affected_url_stats = build_affected_url_stats(findings);
    let attack_chains = build_attack_chains(findings);
    let suspicious_processes = findings
        .iter()
        .filter(|finding| finding.source_type == "process")
        .cloned()
        .collect::<Vec<_>>();
    let suspicious_network = findings
        .iter()
        .filter(|finding| finding.source_type == "network")
        .cloned()
        .collect::<Vec<_>>();
    let suspicious_persistence = findings
        .iter()
        .filter(|finding| finding.source_type == "persistence")
        .cloned()
        .collect::<Vec<_>>();
    let suspicious_app_events = findings
        .iter()
        .filter(|finding| finding.source_type == "app_log")
        .cloned()
        .collect::<Vec<_>>();
    let suspicious_waf_events = findings
        .iter()
        .filter(|finding| finding.source_type == "waf_log")
        .cloned()
        .collect::<Vec<_>>();

    write_high_risk_events_csv(&layout.high_risk_events, &high_risk_events)?;
    write_attack_ip_stats_csv(&layout.attack_ip_stats, &attack_ip_stats)?;
    write_attack_type_stats_csv(&layout.attack_type_stats, &attack_type_stats)?;
    write_suspicious_findings_csv(&layout.suspicious_processes, &suspicious_processes)?;
    write_suspicious_findings_csv(&layout.suspicious_network, &suspicious_network)?;

    if skipped_placeholder_ips > 0 {
        logger.log(format!(
            "correlation: skipped {skipped_placeholder_ips} finding(s) with placeholder remote IP (-/0.0.0.0/unknown/unparseable) in attack IP stats"
        ))?;
    }
    logger.log(format!(
        "correlation: {} relation(s), {} high-risk event(s)",
        relation_count,
        high_risk_events.len()
    ))?;

    Ok(CorrelationReport {
        relation_count,
        high_risk_events,
        attack_ip_stats,
        attack_type_stats,
        affected_url_stats,
        suspicious_processes,
        suspicious_network,
        suspicious_persistence,
        suspicious_app_events,
        suspicious_waf_events,
        recent_web_files,
        suspicious_files,
        attack_chains,
    })
}

fn relation_between(left: &Finding, right: &Finding) -> Option<Relation> {
    if is_http(left) && is_waf(right) {
        return waf_relation(left, right, true);
    }
    if is_http(right) && is_waf(left) {
        return waf_relation(right, left, false);
    }
    if is_http(left) && is_app(right) {
        return app_relation(left, right, true);
    }
    if is_http(right) && is_app(left) {
        return app_relation(right, left, false);
    }

    if (is_http(left) || is_http(right))
        && is_same_remote_ip(left, right)
        && !are_both_ioc(left, right)
        && within_seconds(left, right, HTTP_CONTEXT_WINDOW_SECONDS)
    {
        return Some(Relation {
            reason: "same remote IP produced adjacent suspicious HTTP evidence within 2 minutes"
                .to_string(),
            boost_a: 5,
            boost_b: 5,
        });
    }

    if is_http(left) && is_host_context(right) {
        return host_relation(left, right, true);
    }
    if is_http(right) && is_host_context(left) {
        return host_relation(right, left, false);
    }
    if is_http(left) && is_database(right) {
        return db_relation(left, right, true);
    }
    if is_http(right) && is_database(left) {
        return db_relation(right, left, false);
    }
    if is_http(left) && is_file(right) {
        return file_relation(left, right, true);
    }
    if is_http(right) && is_file(left) {
        return file_relation(right, left, false);
    }

    None
}

fn host_relation(http: &Finding, host: &Finding, http_is_left: bool) -> Option<Relation> {
    let (window_seconds, reason, http_boost, host_boost) = match host.source_type.as_str() {
        "process" => (
            HOST_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with suspicious process evidence within 10 minutes",
            20,
            5,
        ),
        "network" => (
            HOST_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with suspicious network evidence within 10 minutes",
            20,
            5,
        ),
        "persistence" => (
            HOST_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with suspicious persistence evidence within 10 minutes",
            15,
            5,
        ),
        "account" | "logon" => (
            LOGIN_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with account or logon evidence within 30 minutes",
            10,
            5,
        ),
        "windows_event" | "linux_event" => (
            HOST_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with suspicious host event evidence within 10 minutes",
            20,
            5,
        ),
        "container" => (
            HOST_CONTEXT_WINDOW_SECONDS,
            "Web request evidence aligns with suspicious container node-side evidence within 10 minutes",
            15,
            5,
        ),
        _ => return None,
    };

    if !within_seconds(http, host, window_seconds) {
        return None;
    }

    // 共同键约束:纯时间窗会把不同攻击者的证据经 host 证据传递合并成一条链。
    // 双侧都有可比信息时必须一致——remote_ip(占位值视为无信息)canonical 后不等、
    // 或 uri_path 归一化后不等,则不关联;进程类 host finding 无 IP/路径时维持时间窗关联。
    if let (Some(http_ip), Some(host_ip)) = (http.remote_ip.as_deref(), host.remote_ip.as_deref()) {
        if !is_placeholder_ip(http_ip)
            && !is_placeholder_ip(host_ip)
            && normalize_ip_text(http_ip) != normalize_ip_text(host_ip)
        {
            return None;
        }
    }
    if let (Some(http_path), Some(host_path)) = (http.uri_path.as_deref(), host.uri_path.as_deref())
    {
        if !http_path.trim().is_empty()
            && !host_path.trim().is_empty()
            && normalize_uri_path(http_path) != normalize_uri_path(host_path)
        {
            return None;
        }
    }

    let (boost_a, boost_b) = if http_is_left {
        (http_boost, host_boost)
    } else {
        (host_boost, http_boost)
    };
    Some(Relation {
        reason: reason.to_string(),
        boost_a,
        boost_b,
    })
}

fn db_relation(http: &Finding, db: &Finding, http_is_left: bool) -> Option<Relation> {
    if !is_db_relevant_to_http(http, db) || !within_seconds(http, db, db_window_seconds(db)) {
        return None;
    }
    let reason = if http.category == "sqli" {
        "Web SQL injection evidence aligns with suspicious database evidence"
    } else {
        "Web request evidence aligns with suspicious database evidence"
    };
    let (boost_a, boost_b) = if http_is_left { (15, 10) } else { (10, 15) };
    Some(Relation {
        reason: format!("{reason} within {} minutes", db_window_seconds(db) / 60),
        boost_a,
        boost_b,
    })
}

fn waf_relation(http: &Finding, waf: &Finding, http_is_left: bool) -> Option<Relation> {
    if !within_seconds(http, waf, DB_CONTEXT_WINDOW_SECONDS) {
        return None;
    }
    let same_ip = is_same_remote_ip(http, waf);
    let same_path = same_uri_path(http, waf);
    if !same_ip && !same_path {
        return None;
    }

    let mut reason = if same_ip {
        "WAF/CDN evidence aligns with nearby Web access evidence from the same client"
    } else {
        "WAF/CDN evidence aligns with nearby Web access evidence for the same path"
    }
    .to_string();
    if matches!(http.status, Some(200 | 201 | 202 | 500)) {
        reason.push_str("; Web response status warrants bypass or impact review");
    }
    let (boost_a, boost_b) = if http_is_left { (10, 5) } else { (5, 10) };
    Some(Relation {
        reason,
        boost_a,
        boost_b,
    })
}

fn app_relation(http: &Finding, app: &Finding, http_is_left: bool) -> Option<Relation> {
    if !within_seconds(http, app, DB_CONTEXT_WINDOW_SECONDS) {
        return None;
    }
    let relevant_category = matches!(
        http.category.as_str(),
        "sqli" | "rce" | "ssrf" | "framework_probe" | "upload_webshell" | "info_leak"
    );
    let same_path = same_uri_path(http, app);
    let http_error = matches!(http.status, Some(500..=599));
    if !same_path && !http_error && !relevant_category {
        return None;
    }

    let reason = if same_path {
        "Application error evidence aligns with nearby Web request evidence for the same path"
    } else if http_error {
        "Application error evidence aligns with nearby HTTP 5xx evidence"
    } else {
        "Application error evidence aligns with nearby suspicious Web request evidence"
    };
    let (boost_a, boost_b) = if http_is_left { (15, 10) } else { (10, 15) };
    Some(Relation {
        reason: reason.to_string(),
        boost_a,
        boost_b,
    })
}

fn file_relation(http: &Finding, file: &Finding, http_is_left: bool) -> Option<Relation> {
    if !should_link_file_context(http) || !within_seconds(http, file, HOST_CONTEXT_WINDOW_SECONDS) {
        return None;
    }
    let (boost_a, boost_b) = if http_is_left { (20, 10) } else { (10, 20) };
    Some(Relation {
        reason: "Web request evidence aligns with suspicious Web file evidence within 10 minutes"
            .to_string(),
        boost_a,
        boost_b,
    })
}

fn is_db_relevant_to_http(http: &Finding, db: &Finding) -> bool {
    matches!(
        http.category.as_str(),
        "sqli" | "rce" | "upload_webshell" | "framework_probe" | "info_leak"
    ) && db.category.starts_with("db_")
}

fn db_window_seconds(db: &Finding) -> i64 {
    if db.category == "db_auth_failure" {
        15 * 60
    } else {
        DB_CONTEXT_WINDOW_SECONDS
    }
}

fn correlate_file_context(
    findings: &[Finding],
    recent_files: &[CsvRecord],
    suspicious_files: &[CsvRecord],
    context_notes: &mut [Vec<String>],
    boosts: &mut [u16],
) {
    let mut records = Vec::new();
    for record in suspicious_files {
        records.push((record, true));
    }
    for record in recent_files {
        records.push((record, false));
    }

    for (index, finding) in findings.iter().enumerate() {
        if !should_link_file_context(finding) {
            continue;
        }
        let Some(finding_time) = parse_optional_timestamp(finding.timestamp.as_deref()) else {
            continue;
        };

        let mut seen_paths = BTreeSet::new();
        for (record, suspicious) in &records {
            let Some(modified_at) = record.get("modified_at") else {
                continue;
            };
            let Ok(file_time) = crate::time_utils::parse_datetime(modified_at) else {
                continue;
            };
            if timestamp_delta_seconds(finding_time, file_time) > HOST_CONTEXT_WINDOW_SECONDS {
                continue;
            }
            let path = record.get("path").unwrap_or("unknown path");
            if !seen_paths.insert(path.to_string()) {
                continue;
            }
            let reason = record.get("reason").unwrap_or("recent_change");
            context_notes[index].push(format!(
                "file_context: Web file {path} ({reason}) changed within 10 minutes"
            ));
            boosts[index] = boosts[index].saturating_add(if *suspicious { 15 } else { 10 });
            if seen_paths.len() >= 3 {
                break;
            }
        }
    }
}

fn should_link_file_context(finding: &Finding) -> bool {
    is_http(finding)
        && matches!(
            finding.category.as_str(),
            "upload_webshell" | "rce" | "framework_probe" | "lfi"
        )
}

fn build_high_risk_events(
    findings: &[Finding],
    context_notes: &[Vec<String>],
) -> Vec<HighRiskEvent> {
    let by_id = findings
        .iter()
        .map(|finding| (finding.finding_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    let mut rows = findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| is_high_or_critical(finding))
        .map(|(index, finding)| {
            let evidence_chain = build_evidence_chain(finding, &by_id, &context_notes[index]);
            HighRiskEvent {
                finding_id: finding.finding_id.clone(),
                severity: finding.severity.as_str().to_string(),
                confidence: finding.confidence.as_str().to_string(),
                evidence_quality: finding.evidence_quality.as_str().to_string(),
                score: finding.score,
                category: finding.category.clone(),
                rule_id: finding.rule_id.clone(),
                timestamp: finding.timestamp.clone().unwrap_or_default(),
                remote_ip: finding.remote_ip.clone().unwrap_or_default(),
                uri_path: finding.uri_path.clone().unwrap_or_default(),
                source_file: finding.source_file.clone().unwrap_or_default(),
                line_number: finding
                    .line_number
                    .map(|line| line.to_string())
                    .unwrap_or_default(),
                related_ids: finding.related_ids.join(";"),
                evidence_chain_level: finding
                    .evidence_chain_level
                    .clone()
                    .unwrap_or_else(|| "L1".to_string()),
                evidence_chain,
                recommendation: finding.recommendation.clone(),
            }
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    rows
}

fn assign_evidence_chain_levels(findings: &mut [Finding], context_notes: &[Vec<String>]) {
    let snapshot = findings.to_vec();
    let by_id = snapshot
        .iter()
        .map(|finding| (finding.finding_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    for (index, finding) in findings.iter_mut().enumerate() {
        let (level, basis) = evaluate_evidence_chain_level(finding, &by_id, &context_notes[index]);
        finding.evidence_chain_level = Some(level.to_string());
        finding.evidence_chain_basis = Some(basis);
        let quality = evidence_quality_for_level(level, finding);
        finding.set_evidence_quality(
            quality,
            format!(
                "{} {}; chain_level={level}; source_type={}",
                quality.as_str(),
                quality.description(),
                finding.source_type
            ),
        );
    }
}

fn evidence_quality_for_level(level: &str, finding: &Finding) -> crate::model::EvidenceQuality {
    if finding.category == "evidence_gap" || finding.source_type == "evidence_gap" {
        return crate::model::EvidenceQuality::Q5;
    }
    if finding.source_type == "ioc" {
        return crate::model::EvidenceQuality::Q4;
    }
    match level {
        "L5" | "L4" | "L3" => crate::model::EvidenceQuality::Q2,
        "L2" => crate::model::EvidenceQuality::Q3,
        _ => crate::model::default_evidence_quality_for_source(&finding.source_type),
    }
}

fn evaluate_evidence_chain_level(
    finding: &Finding,
    by_id: &BTreeMap<&str, &Finding>,
    context_notes: &[String],
) -> (&'static str, String) {
    let mut source_types = BTreeSet::new();
    source_types.insert(finding.source_type.as_str());
    let mut categories = BTreeSet::new();
    categories.insert(finding.category.as_str());

    for related_id in &finding.related_ids {
        if let Some(related) = by_id.get(related_id.as_str()) {
            source_types.insert(related.source_type.as_str());
            categories.insert(related.category.as_str());
        }
    }

    let has_http = source_types.contains("access_log");
    let has_cross_log = source_types
        .iter()
        .any(|source_type| matches!(*source_type, "db_log" | "app_log" | "waf_log" | "ioc"));
    let has_host_source = source_types.iter().any(|source_type| {
        matches!(
            *source_type,
            "file" | "process" | "network" | "persistence" | "account" | "logon"
        )
    });
    let has_file_context = context_notes
        .iter()
        .any(|note| note.starts_with("file_context:"));
    let has_same_origin_aggregation = context_notes
        .iter()
        .any(|note| note.contains("same remote IP produced adjacent suspicious HTTP evidence"));
    let has_multi_source = source_types.len() >= 2 || !finding.related_ids.is_empty();
    let has_host = has_host_source || has_file_context;
    let has_landing = source_types.contains("file") || has_file_context;
    let has_execution = source_types.contains("process");
    let has_externalization =
        source_types.contains("network") || source_types.contains("persistence");

    let (level, label) = if has_http && has_landing && has_execution && has_externalization {
        ("L5", "complete attack chain")
    } else if has_multi_source && has_host {
        ("L4", "host behavior correlation")
    } else if has_multi_source && (has_cross_log || source_types.len() >= 2) {
        ("L3", "cross-log correlation")
    } else if has_same_origin_aggregation || finding.related_ids.len() > 1 {
        ("L2", "same-origin aggregation")
    } else {
        ("L1", "single evidence point")
    };

    let sources = source_types.into_iter().collect::<Vec<_>>().join("+");
    let related = if finding.related_ids.is_empty() {
        "none".to_string()
    } else {
        finding.related_ids.join(";")
    };
    let mut basis = format!("{level} {label}; sources={sources}; related={related}");
    if !context_notes.is_empty() {
        let notes = context_notes
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        basis.push_str("; context=");
        basis.push_str(&notes);
    }
    (level, basis)
}

fn build_evidence_chain(
    finding: &Finding,
    by_id: &BTreeMap<&str, &Finding>,
    context_notes: &[String],
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("primary: {}", finding.evidence_summary));
    if let Some(source_file) = &finding.source_file {
        let line = finding
            .line_number
            .map(|line| format!(" line {line}"))
            .unwrap_or_default();
        let hash = finding
            .raw_hash
            .as_ref()
            .map(|hash| format!(" hash {hash}"))
            .unwrap_or_default();
        parts.push(format!("source: {source_file}{line}{hash}"));
    }
    for related_id in &finding.related_ids {
        if let Some(related) = by_id.get(related_id.as_str()) {
            parts.push(format!(
                "related {related_id}: {} {} score {}",
                related.source_type, related.category, related.score
            ));
        }
    }
    parts.extend(context_notes.iter().take(6).cloned());
    parts.push(
        "interpretation: suspicious evidence requiring manual review, not proof of compromise"
            .to_string(),
    );
    parts.join(" | ")
}

fn build_attack_ip_stats(findings: &[Finding]) -> (Vec<AttackIpStat>, usize) {
    let mut groups: BTreeMap<String, FindingStats> = BTreeMap::new();
    let mut skipped_placeholder = 0usize;
    for finding in findings {
        let Some(remote_ip) = finding.remote_ip.as_ref().filter(|value| !value.is_empty()) else {
            continue;
        };
        // 占位 IP 不是真实攻击来源,不进攻击 IP 统计(跳过数返回给调用方记录)。
        if is_placeholder_ip(remote_ip) {
            skipped_placeholder += 1;
            continue;
        }
        groups
            .entry(remote_ip.clone())
            .or_default()
            .add(finding, Some(remote_ip));
    }

    let mut rows = groups
        .into_iter()
        .map(|(remote_ip, stats)| AttackIpStat {
            remote_ip,
            findings: stats.findings,
            total_score: stats.total_score,
            max_score: stats.max_score,
            highest_severity: Severity::from_score(stats.max_score).as_str().to_string(),
            categories: join_set(&stats.categories),
            top_paths: join_limited(&stats.paths, 5),
            first_seen: stats.first_seen.unwrap_or_default(),
            last_seen: stats.last_seen.unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        right
            .max_score
            .cmp(&left.max_score)
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.remote_ip.cmp(&right.remote_ip))
    });
    (rows, skipped_placeholder)
}

fn build_attack_type_stats(findings: &[Finding]) -> Vec<AttackTypeStat> {
    let mut groups: BTreeMap<String, FindingStats> = BTreeMap::new();
    for finding in findings {
        groups
            .entry(finding.category.clone())
            .or_default()
            .add(finding, finding.remote_ip.as_ref());
    }

    let mut rows = groups
        .into_iter()
        .map(|(category, stats)| AttackTypeStat {
            category,
            findings: stats.findings,
            high_or_critical: stats.high_or_critical,
            max_score: stats.max_score,
            highest_severity: Severity::from_score(stats.max_score).as_str().to_string(),
            affected_ips: join_limited(&stats.remote_ips, 10),
            affected_paths: join_limited(&stats.paths, 10),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .max_score
            .cmp(&left.max_score)
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.category.cmp(&right.category))
    });
    rows
}

fn build_affected_url_stats(findings: &[Finding]) -> Vec<AffectedUrlStat> {
    let mut groups: BTreeMap<String, FindingStats> = BTreeMap::new();
    for finding in findings {
        let Some(uri_path) = finding.uri_path.as_ref().filter(|value| !value.is_empty()) else {
            continue;
        };
        groups
            .entry(uri_path.clone())
            .or_default()
            .add(finding, finding.remote_ip.as_ref());
    }

    let mut rows = groups
        .into_iter()
        .map(|(uri_path, stats)| AffectedUrlStat {
            uri_path,
            findings: stats.findings,
            max_score: stats.max_score,
            categories: join_set(&stats.categories),
            remote_ips: join_limited(&stats.remote_ips, 10),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .max_score
            .cmp(&left.max_score)
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.uri_path.cmp(&right.uri_path))
    });
    rows
}

fn build_attack_chains(findings: &[Finding]) -> Vec<AttackChain> {
    let mut index_by_id = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        index_by_id.insert(finding.finding_id.as_str(), index);
    }

    let mut parent = (0..findings.len()).collect::<Vec<_>>();
    for (index, finding) in findings.iter().enumerate() {
        for related_id in &finding.related_ids {
            if let Some(&related_index) = index_by_id.get(related_id.as_str()) {
                union(&mut parent, index, related_index);
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<&Finding>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        let root = find_root(&mut parent, index);
        groups.entry(root).or_default().push(finding);
    }

    let mut chains = groups
        .into_values()
        .filter(|group| group.len() > 1)
        .enumerate()
        .map(|(index, mut group)| {
            group.sort_by_key(|finding| finding_sort_key(finding));
            let mut stats = FindingStats::default();
            let mut levels = BTreeSet::new();
            let mut bases = Vec::new();
            let mut ids = Vec::new();
            for finding in &group {
                stats.add(finding, finding.remote_ip.as_ref());
                ids.push(finding.finding_id.clone());
                if let Some(level) = finding.evidence_chain_level.as_deref() {
                    levels.insert(level.to_string());
                }
                if let Some(basis) = finding.evidence_chain_basis.as_deref() {
                    bases.push(format!("{}: {basis}", finding.finding_id));
                }
            }
            let evidence_chain_level = levels
                .iter()
                .max_by_key(|level| evidence_level_rank(level))
                .cloned()
                .unwrap_or_else(|| "L1".to_string());
            let summary = group
                .iter()
                .take(6)
                .map(|finding| {
                    format!(
                        "{} {} {} score {}",
                        finding.timestamp.as_deref().unwrap_or("undated"),
                        finding.source_type,
                        finding.rule_id,
                        finding.score
                    )
                })
                .collect::<Vec<_>>()
                .join(" -> ");
            AttackChain {
                chain_id: format!("CHAIN-{:06}", index + 1),
                evidence_chain_level,
                evidence_chain_basis: bases.into_iter().take(5).collect::<Vec<_>>().join(" | "),
                max_score: stats.max_score,
                highest_severity: Severity::from_score(stats.max_score).as_str().to_string(),
                first_seen: stats.first_seen.unwrap_or_default(),
                last_seen: stats.last_seen.unwrap_or_default(),
                remote_ips: join_limited(&stats.remote_ips, 10),
                paths: join_limited(&stats.paths, 10),
                categories: join_set(&stats.categories),
                finding_ids: ids,
                summary,
            }
        })
        .collect::<Vec<_>>();

    chains.sort_by(|left, right| {
        evidence_level_rank(&right.evidence_chain_level)
            .cmp(&evidence_level_rank(&left.evidence_chain_level))
            .then_with(|| right.max_score.cmp(&left.max_score))
            .then_with(|| left.chain_id.cmp(&right.chain_id))
    });
    chains
}

/// 攻击链内按绝对时刻排序:Some(nanos)→(0, nanos),无/不可解析→(1, 0) 恒排最后。
/// 等价于旧 "9999" 哨兵语义,但混合时区偏移时依然正确。
fn finding_sort_key(finding: &Finding) -> ((u8, i128), String) {
    (
        match crate::time_utils::timestamp_instant_nanos(finding.timestamp.as_deref()) {
            Some(nanos) => (0, nanos),
            None => (1, 0),
        },
        finding.finding_id.clone(),
    )
}

fn evidence_level_rank(level: &str) -> u8 {
    match level {
        "L5" => 5,
        "L4" => 4,
        "L3" => 3,
        "L2" => 2,
        _ => 1,
    }
}

fn union(parent: &mut [usize], left: usize, right: usize) {
    let left_root = find_root(parent, left);
    let right_root = find_root(parent, right);
    if left_root != right_root {
        parent[right_root] = left_root;
    }
}

fn find_root(parent: &mut [usize], index: usize) -> usize {
    if parent[index] != index {
        parent[index] = find_root(parent, parent[index]);
    }
    parent[index]
}

#[derive(Debug, Default)]
struct FindingStats {
    findings: usize,
    total_score: u64,
    max_score: u16,
    high_or_critical: usize,
    categories: BTreeSet<String>,
    remote_ips: BTreeSet<String>,
    paths: BTreeSet<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
    first_seen_nanos: Option<i128>,
    last_seen_nanos: Option<i128>,
}

impl FindingStats {
    fn add(&mut self, finding: &Finding, remote_ip: Option<&String>) {
        self.findings += 1;
        self.total_score += u64::from(finding.score);
        self.max_score = self.max_score.max(finding.score);
        if is_high_or_critical(finding) {
            self.high_or_critical += 1;
        }
        self.categories.insert(finding.category.clone());
        if let Some(remote_ip) = remote_ip.filter(|value| !value.is_empty()) {
            self.remote_ips.insert(remote_ip.clone());
        }
        if let Some(path) = finding.uri_path.as_ref().filter(|value| !value.is_empty()) {
            self.paths.insert(path.clone());
        }
        if let Some(timestamp) = &finding.timestamp {
            // 用解析后的绝对时刻比较并保留对应原字符串:
            // 混合 +08:00 与 Z 偏移时,字符串字典序与真实时间序不一致。
            let Some(nanos) = crate::time_utils::timestamp_instant_nanos(Some(timestamp.as_str()))
            else {
                return;
            };
            if self
                .first_seen_nanos
                .map(|seen| nanos < seen)
                .unwrap_or(true)
            {
                self.first_seen_nanos = Some(nanos);
                self.first_seen = Some(timestamp.clone());
            }
            if self.last_seen_nanos.map(|seen| nanos > seen).unwrap_or(true) {
                self.last_seen_nanos = Some(nanos);
                self.last_seen = Some(timestamp.clone());
            }
        }
    }
}

fn append_correlation_summary(finding: &mut Finding, context_notes: &[String]) {
    let notes = context_notes
        .iter()
        .take(4)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    if notes.is_empty() {
        return;
    }
    finding.evidence_summary.push_str(" Correlation context: ");
    finding.evidence_summary.push_str(&notes);
    finding.evidence_summary.push('.');
}

fn is_same_remote_ip(left: &Finding, right: &Finding) -> bool {
    let (Some(left_ip), Some(right_ip)) = (left.remote_ip.as_deref(), right.remote_ip.as_deref())
    else {
        return false;
    };
    // 占位 IP(-、0.0.0.0、unknown、空、不可解析)不含真实来源信息,
    // 不能因为字符串相等就当成同一攻击者互相关联。
    if is_placeholder_ip(left_ip) || is_placeholder_ip(right_ip) {
        return false;
    }
    normalize_ip_text(left_ip) == normalize_ip_text(right_ip)
}

/// 占位 IP:- / 0.0.0.0(及 ::)/ unknown / 空 / 完全不可解析的值。
fn is_placeholder_ip(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.eq_ignore_ascii_case("unknown") {
        return true;
    }
    match canonical_ip(trimmed) {
        None => true,
        Some(ip) => match ip {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        },
    }
}

/// 字符串 normalize:解析成功则用 canonical 形式比较,
/// 使 ::ffff:1.2.3.4 与 1.2.3.4 判等。
fn normalize_ip_text(value: &str) -> String {
    match canonical_ip(value) {
        Some(ip) => ip.to_string(),
        None => value.trim().to_string(),
    }
}

fn is_http(finding: &Finding) -> bool {
    finding.source_type == "access_log"
}

fn is_host_context(finding: &Finding) -> bool {
    matches!(
        finding.source_type.as_str(),
        "process"
            | "network"
            | "persistence"
            | "account"
            | "logon"
            | "windows_event"
            | "linux_event"
            | "container"
    )
}

fn is_database(finding: &Finding) -> bool {
    finding.source_type == "db_log"
}

fn is_waf(finding: &Finding) -> bool {
    finding.source_type == "waf_log"
}

fn is_app(finding: &Finding) -> bool {
    finding.source_type == "app_log"
}

fn is_file(finding: &Finding) -> bool {
    finding.source_type == "file"
}

fn same_uri_path(left: &Finding, right: &Finding) -> bool {
    matches!(
        (left.uri_path.as_deref(), right.uri_path.as_deref()),
        (Some(left_path), Some(right_path))
            if !left_path.is_empty()
                && !right_path.is_empty()
                && normalize_uri_path(left_path) == normalize_uri_path(right_path)
    )
}

/// URI 归一化(percent-decode + 消解 ./.. 段 + 合并重复斜杠),
/// 让 "/a/./b"、"/a//b"、"/a/%62" 与 "/a/b" 视为同一路径。
fn normalize_uri_path(path: &str) -> String {
    let decoded = percent_decode(path.trim());
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    format!("/{}", segments.join("/"))
}

/// 简单 percent-decode:仅在两个十六进制位都合法时解码,其余按原字节保留。
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn are_both_ioc(left: &Finding, right: &Finding) -> bool {
    left.source_type == "ioc" && right.source_type == "ioc"
}

fn within_seconds(left: &Finding, right: &Finding, window_seconds: i64) -> bool {
    let Some(left_time) = parse_optional_timestamp(left.timestamp.as_deref()) else {
        return false;
    };
    let Some(right_time) = parse_optional_timestamp(right.timestamp.as_deref()) else {
        return false;
    };
    timestamp_delta_seconds(left_time, right_time) <= window_seconds
}

fn parse_optional_timestamp(value: Option<&str>) -> Option<time::OffsetDateTime> {
    value.and_then(|value| crate::time_utils::parse_datetime(value).ok())
}

fn timestamp_delta_seconds(left: time::OffsetDateTime, right: time::OffsetDateTime) -> i64 {
    left.unix_timestamp()
        .saturating_sub(right.unix_timestamp())
        .abs()
}

fn is_high_or_critical(finding: &Finding) -> bool {
    if finding.category == "evidence_gap" {
        return false;
    }
    matches!(finding.severity, Severity::High | Severity::Critical) || finding.score >= 70
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(";")
}

fn join_limited(values: &BTreeSet<String>, limit: usize) -> String {
    values
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(";")
}

fn read_csv_records(path: &Path) -> Result<Vec<CsvRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    let headers = reader.headers()?.clone();
    let mut rows = Vec::new();
    for row in reader.records().flatten() {
        let mut fields = BTreeMap::new();
        for (header, value) in headers.iter().zip(row.iter()) {
            fields.insert(normalize_field_name(header), value.trim().to_string());
        }
        rows.push(CsvRecord { fields });
    }
    Ok(rows)
}

fn normalize_field_name(key: &str) -> String {
    key.trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .replace(['-', ' '], "_")
}

fn write_high_risk_events_csv(path: &Path, rows: &[HighRiskEvent]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "finding_id",
        "severity",
        "confidence",
        "evidence_quality",
        "score",
        "category",
        "rule_id",
        "timestamp",
        "remote_ip",
        "uri_path",
        "source_file",
        "line_number",
        "related_ids",
        "evidence_chain_level",
        "evidence_chain",
        "recommendation",
    ])?;
    for row in rows {
        writer.write_record([
            row.finding_id.as_str(),
            row.severity.as_str(),
            row.confidence.as_str(),
            row.evidence_quality.as_str(),
            &row.score.to_string(),
            row.category.as_str(),
            row.rule_id.as_str(),
            row.timestamp.as_str(),
            row.remote_ip.as_str(),
            row.uri_path.as_str(),
            row.source_file.as_str(),
            row.line_number.as_str(),
            row.related_ids.as_str(),
            row.evidence_chain_level.as_str(),
            row.evidence_chain.as_str(),
            row.recommendation.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_attack_ip_stats_csv(path: &Path, rows: &[AttackIpStat]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "remote_ip",
        "findings",
        "total_score",
        "max_score",
        "highest_severity",
        "categories",
        "top_paths",
        "first_seen",
        "last_seen",
    ])?;
    for row in rows {
        writer.write_record([
            row.remote_ip.as_str(),
            &row.findings.to_string(),
            &row.total_score.to_string(),
            &row.max_score.to_string(),
            row.highest_severity.as_str(),
            row.categories.as_str(),
            row.top_paths.as_str(),
            row.first_seen.as_str(),
            row.last_seen.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_attack_type_stats_csv(path: &Path, rows: &[AttackTypeStat]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "category",
        "findings",
        "high_or_critical",
        "max_score",
        "highest_severity",
        "affected_ips",
        "affected_paths",
    ])?;
    for row in rows {
        writer.write_record([
            row.category.as_str(),
            &row.findings.to_string(),
            &row.high_or_critical.to_string(),
            &row.max_score.to_string(),
            row.highest_severity.as_str(),
            row.affected_ips.as_str(),
            row.affected_paths.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_suspicious_findings_csv(path: &Path, rows: &[Finding]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "finding_id",
        "severity",
        "confidence",
        "evidence_quality",
        "score",
        "category",
        "rule_id",
        "source_file",
        "line_number",
        "evidence_summary",
        "raw_hash",
        "recommendation",
    ])?;
    for row in rows {
        writer.write_record([
            row.finding_id.as_str(),
            row.severity.as_str(),
            row.confidence.as_str(),
            row.evidence_quality.as_str(),
            &row.score.to_string(),
            row.category.as_str(),
            row.rule_id.as_str(),
            row.source_file.as_deref().unwrap_or_default(),
            &row.line_number
                .map(|line| line.to_string())
                .unwrap_or_default(),
            row.evidence_summary.as_str(),
            row.raw_hash.as_deref().unwrap_or_default(),
            row.recommendation.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_empty_m7_tables(layout: &OutputLayout) -> Result<()> {
    writers::write_text(
        &layout.high_risk_events,
        "finding_id,severity,confidence,evidence_quality,score,category,rule_id,timestamp,remote_ip,uri_path,source_file,line_number,related_ids,evidence_chain_level,evidence_chain,recommendation\n",
    )?;
    writers::write_text(
        &layout.attack_ip_stats,
        "remote_ip,findings,total_score,max_score,highest_severity,categories,top_paths,first_seen,last_seen\n",
    )?;
    writers::write_text(
        &layout.attack_type_stats,
        "category,findings,high_or_critical,max_score,highest_severity,affected_ips,affected_paths\n",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, EvidenceQuality, ScoreBreakdown};

    fn test_finding(
        finding_id: &str,
        source_type: &str,
        timestamp: Option<&str>,
        remote_ip: Option<&str>,
        uri_path: Option<&str>,
    ) -> Finding {
        Finding {
            finding_id: finding_id.to_string(),
            timestamp: timestamp.map(str::to_string),
            severity: Severity::Medium,
            score: 50,
            confidence: Confidence::Medium,
            evidence_quality: EvidenceQuality::Q2,
            evidence_quality_basis: String::new(),
            score_breakdown: ScoreBreakdown::from_final_score(50),
            category: "rce".to_string(),
            rule_id: "RULE-001".to_string(),
            rule_name: "rule".to_string(),
            source_type: source_type.to_string(),
            source_file: Some("evidence.log".to_string()),
            line_number: Some(1),
            remote_ip: remote_ip.map(str::to_string),
            method: None,
            uri_path: uri_path.map(str::to_string),
            status: None,
            evidence_summary: "test".to_string(),
            raw_hash: Some("hash".to_string()),
            related_ids: Vec::new(),
            evidence_chain_level: None,
            evidence_chain_basis: None,
            recommendation: String::new(),
        }
    }

    #[test]
    fn placeholder_ips_never_link_as_same_attacker() {
        for placeholder in ["-", "0.0.0.0", "unknown", ""] {
            let left = test_finding("F-1", "access_log", Some("2026-08-27T08:00:00Z"), Some(placeholder), Some("/a"));
            let right = test_finding("F-2", "access_log", Some("2026-08-27T08:00:30Z"), Some(placeholder), Some("/b"));
            assert!(is_placeholder_ip(placeholder), "{placeholder:?} should be placeholder");
            assert!(!is_same_remote_ip(&left, &right));
            assert!(relation_between(&left, &right).is_none());
        }
    }

    #[test]
    fn same_remote_ip_canonicalizes_v4_mapped_ipv6() {
        let left = test_finding(
            "F-1",
            "access_log",
            Some("2026-08-27T08:00:00Z"),
            Some("203.0.113.10"),
            Some("/a"),
        );
        let right = test_finding(
            "F-2",
            "access_log",
            Some("2026-08-27T08:00:30Z"),
            Some("::ffff:203.0.113.10"),
            None,
        );
        assert!(is_same_remote_ip(&left, &right));
        assert!(relation_between(&left, &right).is_some());

        let other = test_finding(
            "F-3",
            "access_log",
            Some("2026-08-27T08:00:30Z"),
            Some("203.0.113.11"),
            None,
        );
        assert!(!is_same_remote_ip(&left, &other));
    }

    #[test]
    fn attack_ip_stats_skip_placeholder_rows() {
        let findings = vec![
            test_finding("F-1", "access_log", Some("2026-08-27T08:00:00Z"), Some("203.0.113.10"), Some("/a")),
            test_finding("F-2", "access_log", Some("2026-08-27T08:01:00Z"), Some("0.0.0.0"), Some("/b")),
            test_finding("F-3", "access_log", Some("2026-08-27T08:02:00Z"), Some("-"), None),
        ];
        let (rows, skipped) = build_attack_ip_stats(&findings);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].remote_ip, "203.0.113.10");
        assert_eq!(skipped, 2);
    }

    #[test]
    fn host_relation_requires_shared_keys_when_both_present() {
        let http = test_finding(
            "F-1",
            "access_log",
            Some("2026-08-27T08:00:00Z"),
            Some("203.0.113.10"),
            Some("/api/run"),
        );
        // host finding 携带不同 remote_ip:不关联。
        let host_other_ip = test_finding(
            "F-2",
            "process",
            Some("2026-08-27T08:01:00Z"),
            Some("198.51.100.7"),
            None,
        );
        assert!(relation_between(&http, &host_other_ip).is_none());

        // host finding 携带不同 uri_path:不关联。
        let host_other_path = test_finding(
            "F-3",
            "network",
            Some("2026-08-27T08:01:00Z"),
            None,
            Some("/other/path"),
        );
        assert!(relation_between(&http, &host_other_path).is_none());

        // host finding 无 IP/路径(进程类常见形态):维持时间窗关联。
        let host_bare = test_finding("F-4", "process", Some("2026-08-27T08:01:00Z"), None, None);
        assert!(relation_between(&http, &host_bare).is_some());

        // IP 一致(v4-mapped 写法)时仍关联。
        let host_same_ip = test_finding(
            "F-5",
            "process",
            Some("2026-08-27T08:01:00Z"),
            Some("::ffff:203.0.113.10"),
            None,
        );
        assert!(relation_between(&http, &host_same_ip).is_some());
    }

    #[test]
    fn uri_path_normalization_collapses_equivalent_writings() {
        assert_eq!(normalize_uri_path("/a/./b"), "/a/b");
        assert_eq!(normalize_uri_path("/a//b"), "/a/b");
        assert_eq!(normalize_uri_path("/a/%62/../c"), "/a/c");
        assert_eq!(normalize_uri_path("a/b"), "/a/b");
        assert_ne!(normalize_uri_path("/admin"), normalize_uri_path("/administrator"));
    }

    #[test]
    fn finding_stats_first_last_seen_use_instant_not_lexicographic() {
        let mut stats = FindingStats::default();
        stats.add(
            &test_finding("F-1", "access_log", Some("2026-08-27T21:00:00+08:00"), Some("203.0.113.10"), None),
            None,
        );
        stats.add(
            &test_finding("F-2", "access_log", Some("2026-08-27T05:00:00Z"), Some("203.0.113.10"), None),
            None,
        );
        // 05:00Z 早于 21:00+08:00(=13:00Z);字典序会得出相反结论。
        assert_eq!(stats.first_seen.as_deref(), Some("2026-08-27T05:00:00Z"));
        assert_eq!(stats.last_seen.as_deref(), Some("2026-08-27T21:00:00+08:00"));
    }

    #[test]
    fn finding_sort_key_orders_none_last_and_mixed_offsets() {
        let early = test_finding("F-1", "access_log", Some("2026-08-27T05:00:00Z"), None, None);
        let late = test_finding("F-2", "access_log", Some("2026-08-27T21:00:00+08:00"), None, None);
        let undated = test_finding("F-3", "access_log", None, None, None);
        let unparseable = test_finding("F-4", "access_log", Some("garbage"), None, None);
        assert!(finding_sort_key(&early) < finding_sort_key(&late));
        assert!(finding_sort_key(&late) < finding_sort_key(&undated));
        // 无时间与不可解析同桶(时间分量相同,由后续决胜字段区分)。
        assert_eq!(finding_sort_key(&undated).0, finding_sort_key(&unparseable).0);
    }
}
