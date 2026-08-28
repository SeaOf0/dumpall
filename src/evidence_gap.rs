use sha2::{Digest, Sha256};

use crate::config::ResolvedRun;
use crate::model::{
    CollectionCoverage, CollectionCoverageStatus, CollectionError, Confidence, EvidenceGap,
    EvidenceQuality, Finding, ScoreBreakdown, Severity,
};

pub fn build_evidence_gaps(
    resolved: &ResolvedRun,
    collection_errors: &[CollectionError],
) -> Vec<EvidenceGap> {
    let mut gaps = collection_errors
        .iter()
        .filter(|error| should_emit_gap(resolved, error))
        .enumerate()
        .map(|(index, error)| gap_from_error(index + 1, error))
        .collect::<Vec<_>>();
    add_expected_source_gaps(resolved, &mut gaps);
    gaps
}

pub fn build_collection_coverage(
    resolved: &ResolvedRun,
    gaps: &[EvidenceGap],
) -> Vec<CollectionCoverage> {
    let mut coverage = Vec::new();
    coverage.push(CollectionCoverage {
        scope: "core_collection".to_string(),
        status: status_for_scope(
            gaps,
            &[
                "system",
                "process",
                "network",
                "account",
                "persistence",
                "filesystem",
            ],
        ),
        expected: resolved.mode != crate::model::RunMode::Analyze,
        records_collected: 0,
        gaps: gaps
            .iter()
            .filter(|gap| {
                matches!(
                    gap.source.as_str(),
                    "system" | "process" | "network" | "account" | "persistence" | "filesystem"
                )
            })
            .cloned()
            .collect(),
    });
    if resolved.runtime_scan_enabled() {
        coverage.push(CollectionCoverage {
            scope: "runtime".to_string(),
            status: status_for_scope(gaps, &["runtime"]),
            expected: true,
            records_collected: 0,
            gaps: gaps
                .iter()
                .filter(|gap| gap.source == "runtime")
                .cloned()
                .collect(),
        });
    }
    if resolved.host_events_enabled() {
        coverage.push(CollectionCoverage {
            scope: "host_events".to_string(),
            status: status_for_scope(gaps, &["events", "windows_evtx", "linux_audit", "journald"]),
            expected: true,
            records_collected: 0,
            gaps: gaps
                .iter()
                .filter(|gap| {
                    matches!(
                        gap.source.as_str(),
                        "events" | "windows_evtx" | "linux_audit" | "journald"
                    )
                })
                .cloned()
                .collect(),
        });
    }
    if resolved.container_enabled() {
        coverage.push(CollectionCoverage {
            scope: "container".to_string(),
            status: status_for_scope(gaps, &["container"]),
            expected: true,
            records_collected: 0,
            gaps: gaps
                .iter()
                .filter(|gap| gap.source == "container")
                .cloned()
                .collect(),
        });
    }
    coverage
}

pub fn findings_from_gaps(gaps: &[EvidenceGap], starting_index: usize) -> Vec<Finding> {
    gaps.iter()
        .enumerate()
        .map(|(offset, gap)| finding_from_gap(gap, starting_index + offset + 1))
        .collect()
}

fn should_emit_gap(resolved: &ResolvedRun, error: &CollectionError) -> bool {
    if is_optional_capability_error(error) {
        return false;
    }
    // 配置/输入类错误不是采集缺口:可信代理/GeoIP/IOC 的加载与解析失败
    // 只说明用户提供的配置有问题(仍记录在 collection_errors.csv 可见),
    // 提升为 Q5 gap 会淹没真实采集缺口。
    if matches!(
        error.source.as_str(),
        "trusted_proxy" | "geoip" | "ioc" | "enrich"
    ) || is_config_input_error(error)
    {
        return false;
    }
    if resolved.mode == crate::model::RunMode::Analyze
        && matches!(
            error.source.as_str(),
            "system" | "process" | "network" | "account" | "persistence" | "filesystem"
        )
    {
        return false;
    }
    true
}

/// "could not (be) parse(d)" / "not found" 一类的加载与输入错误:
/// 属于配置修正项而非证据源缺口,不提升为 Q5。
fn is_config_input_error(error: &CollectionError) -> bool {
    let message = error.message.to_ascii_lowercase();
    message.contains("could not parse")
        || message.contains("could not be parsed")
        || message.contains("not found")
}

fn add_expected_source_gaps(resolved: &ResolvedRun, gaps: &mut Vec<EvidenceGap>) {
    // triage 模式由自动发现兜底（winevt 目录、journald 自动导出、容器 socket 等），
    // 不以"用户未显式供路径"为由提升 Q5 缺口，避免淹没真实证据缺口。
    let auto_discovery_mode = resolved.mode == crate::model::RunMode::Triage;
    if resolved.host_events_enabled() {
        if resolved.evtx_paths.is_empty()
            && resolved.journal_paths.is_empty()
            && resolved.audit_log_paths.is_empty()
        {
            if !auto_discovery_mode {
                gaps.push(expected_gap(
                    gaps.len() + 1,
                    "events",
                    "host event sources",
                    "discover",
                    "host-ir profile was enabled but no EVTX, journald, or auditd path was supplied; offline event evidence was not collected in this milestone",
                    "Provide --evtx-path, --journal-path, or --audit-log-path when offline event evidence is available.",
                ));
            }
        } else {
            for path in &resolved.evtx_paths {
                if !path.exists() {
                    let path = path.display().to_string();
                    if !has_gap(gaps, "windows_evtx", &path) {
                        gaps.push(expected_gap(
                            gaps.len() + 1,
                            "windows_evtx",
                            &path,
                            "discover",
                            "EVTX path does not exist",
                            "Verify the offline EVTX export path or rerun with a readable file/directory.",
                        ));
                    }
                }
            }
            for path in &resolved.journal_paths {
                if !path.exists() {
                    let path = path.display().to_string();
                    if !has_gap(gaps, "journald", &path) {
                        gaps.push(expected_gap(
                            gaps.len() + 1,
                            "journald",
                            &path,
                            "discover",
                            "journald path does not exist",
                            "Verify the offline journald export path or rerun with a readable file/directory.",
                        ));
                    }
                }
            }
            for path in &resolved.audit_log_paths {
                if !path.exists() {
                    let path = path.display().to_string();
                    if !has_gap(gaps, "linux_audit", &path) {
                        gaps.push(expected_gap(
                            gaps.len() + 1,
                            "linux_audit",
                            &path,
                            "discover",
                            "audit log path does not exist",
                            "Verify the auditd/auth log path or rerun with a readable file.",
                        ));
                    }
                }
            }
        }
    }

    if !auto_discovery_mode
        && resolved.runtime_scan_enabled()
        && resolved.tomcat_base.is_empty()
        && resolved.spring_app_path.is_empty()
        && resolved.iis_config.is_none()
        && resolved.java_home.is_none()
        && resolved.component_baseline.is_none()
    {
        gaps.push(expected_gap(
            gaps.len() + 1,
            "runtime",
            "runtime component sources",
            "discover",
            "runtime profile was enabled but no Tomcat, Spring, IIS, Java, or component baseline path was supplied; runtime component evidence was not collected in this milestone",
            "Provide --tomcat-base, --spring-app-path, --iis-config, --java-home, or --component-baseline when runtime evidence is available.",
        ));
    }

    if !auto_discovery_mode
        && resolved.container_enabled()
        && resolved.container_log_paths.is_empty()
        && resolved.k8s_node_paths.is_empty()
    {
        gaps.push(expected_gap(
            gaps.len() + 1,
            "container",
            "container runtime sources",
            "discover",
            "container-ir profile was enabled but no container log or Kubernetes node path was supplied; container-side evidence was not collected in this milestone",
            "Provide --container-log-path or --k8s-node-path when node-side container evidence is available.",
        ));
    }
}

fn has_gap(gaps: &[EvidenceGap], source: &str, path: &str) -> bool {
    gaps.iter()
        .any(|gap| gap.source == source && gap.path == path)
}

fn expected_gap(
    index: usize,
    source: &str,
    path: &str,
    operation: &str,
    message: &str,
    detail: &str,
) -> EvidenceGap {
    gap_from_error(
        index,
        &CollectionError {
            timestamp: crate::time_utils::now_iso(),
            source: source.to_string(),
            path: path.to_string(),
            operation: operation.to_string(),
            message: message.to_string(),
            detail: Some(detail.to_string()),
        },
    )
}

fn is_optional_capability_error(error: &CollectionError) -> bool {
    matches!(error.source.as_str(), "yara" | "geoip")
        && error.operation == "initialize"
        && error.message.to_ascii_lowercase().contains("not compiled")
}

fn gap_from_error(index: usize, error: &CollectionError) -> EvidenceGap {
    EvidenceGap {
        gap_id: format!("GAP-{index:06}"),
        timestamp: error.timestamp.clone(),
        source: normalize_source(&error.source),
        path: error.path.clone(),
        operation: error.operation.clone(),
        message: error.message.clone(),
        detail: error.detail.clone(),
        coverage_status: coverage_status_for_error(error),
        confidence: Confidence::High,
        evidence_quality: EvidenceQuality::Q5,
        recommendation: recommendation_for_error(error),
    }
}

fn finding_from_gap(gap: &EvidenceGap, index: usize) -> Finding {
    let score = 10;
    Finding {
        finding_id: format!("GAP-F-{index:06}"),
        timestamp: Some(gap.timestamp.clone()),
        severity: Severity::Info,
        score,
        confidence: gap.confidence,
        evidence_quality: gap.evidence_quality,
        evidence_quality_basis: "Q5 collection gap: the tool could not collect or parse a requested evidence source".to_string(),
        score_breakdown: {
            let mut breakdown = ScoreBreakdown::from_base(score);
            breakdown.add_evidence_gap_discount(5);
            breakdown
        },
        category: "evidence_gap".to_string(),
        rule_id: format!("GAP-{}-UNAVAILABLE-001", rule_source_token(&gap.source)),
        rule_name: "Evidence source unavailable or incomplete".to_string(),
        source_type: "evidence_gap".to_string(),
        source_file: (!gap.path.is_empty()).then(|| gap.path.clone()),
        line_number: None,
        remote_ip: None,
        method: None,
        uri_path: None,
        status: None,
        evidence_summary: format!(
            "Evidence gap in {} during {} on {}: {}. This means the run cannot confirm absence of evidence for that source.",
            gap.source,
            gap.operation,
            if gap.path.is_empty() { "unspecified path" } else { gap.path.as_str() },
            gap.message
        ),
        raw_hash: Some(hash_gap(gap)),
        related_ids: Vec::new(),
        evidence_chain_level: Some("L1".to_string()),
        evidence_chain_basis: Some("L1 evidence gap; sources=evidence_gap; related=none".to_string()),
        recommendation: gap.recommendation.clone(),
    }
}

fn coverage_status_for_error(error: &CollectionError) -> CollectionCoverageStatus {
    let message = error.message.to_ascii_lowercase();
    let operation = error.operation.to_ascii_lowercase();
    if message.contains("not supported") || message.contains("not compiled") {
        CollectionCoverageStatus::Unsupported
    } else if message.contains("does not exist")
        || message.contains("missing")
        || operation.contains("discover")
    {
        CollectionCoverageStatus::NotCollected
    } else {
        CollectionCoverageStatus::Partial
    }
}

fn status_for_scope(gaps: &[EvidenceGap], sources: &[&str]) -> CollectionCoverageStatus {
    let matching = gaps
        .iter()
        .filter(|gap| sources.iter().any(|source| *source == gap.source))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        CollectionCoverageStatus::Collected
    } else if matching
        .iter()
        .all(|gap| gap.coverage_status == CollectionCoverageStatus::Unsupported)
    {
        CollectionCoverageStatus::Unsupported
    } else if matching
        .iter()
        .any(|gap| gap.coverage_status == CollectionCoverageStatus::NotCollected)
    {
        CollectionCoverageStatus::NotCollected
    } else {
        CollectionCoverageStatus::Partial
    }
}

fn normalize_source(source: &str) -> String {
    source.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn rule_source_token(source: &str) -> String {
    source
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn recommendation_for_error(error: &CollectionError) -> String {
    let source = normalize_source(&error.source);
    if matches!(
        source.as_str(),
        "windows_evtx" | "linux_audit" | "journald" | "events"
    ) {
        "Review whether event logs are present, exported, readable, and within the requested time range; absence here is a collection gap, not a clean host signal.".to_string()
    } else if source == "runtime" {
        "Review supplied runtime paths, permissions, and component baseline availability before interpreting runtime results as complete.".to_string()
    } else if source == "container" {
        "Review container runtime metadata paths and log access; this gap means container-side evidence was not fully collected.".to_string()
    } else {
        "Review permissions, path existence, and log availability for this evidence source before treating the run as complete.".to_string()
    }
}

fn hash_gap(gap: &EvidenceGap) -> String {
    let digest = Sha256::digest(
        format!(
            "{}|{}|{}|{}|{}",
            gap.source, gap.path, gap.operation, gap.message, gap.timestamp
        )
        .as_bytes(),
    );
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Commands};
    use crate::config::ResolvedRun;
    use crate::model::RunMode;

    #[test]
    fn optional_yara_feature_gap_is_not_reported_as_evidence_gap() {
        let cli = Cli::parse_from(["dumpall", "analyze", "--log-path", "a.log"]);
        let Commands::Analyze(args) = cli.command else {
            panic!("expected analyze");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &args.common).unwrap();
        let error = CollectionError {
            timestamp: "2026-05-16T00:00:00Z".to_string(),
            source: "yara".to_string(),
            path: "rules.yar".to_string(),
            operation: "initialize".to_string(),
            message:
                "YARA support was requested but this binary was not compiled with the yara feature"
                    .to_string(),
            detail: None,
        };

        assert!(build_evidence_gaps(&resolved, &[error]).is_empty());
    }

    #[test]
    fn explicit_missing_event_path_becomes_q5_gap_finding() {
        let cli = Cli::parse_from([
            "dumpall",
            "scan",
            "--profile",
            "host-ir",
            "--evtx-path",
            "missing.evtx",
        ]);
        let Commands::Scan(args) = cli.command else {
            panic!("expected scan");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &args.common).unwrap();
        let error = CollectionError {
            timestamp: "2026-05-16T00:00:00Z".to_string(),
            source: "windows_evtx".to_string(),
            path: "missing.evtx".to_string(),
            operation: "read".to_string(),
            message: "EVTX path does not exist".to_string(),
            detail: None,
        };

        let gaps = build_evidence_gaps(&resolved, &[error]);
        let findings = findings_from_gaps(&gaps, 10);

        assert_eq!(gaps.len(), 1);
        assert_eq!(findings[0].category, "evidence_gap");
        assert_eq!(findings[0].evidence_quality, EvidenceQuality::Q5);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn config_input_errors_are_not_promoted_to_q5_gaps() {
        let cli = Cli::parse_from(["dumpall", "analyze", "--log-path", "a.log"]);
        let Commands::Analyze(args) = cli.command else {
            panic!("expected analyze");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &args.common).unwrap();

        let errors = vec![
            CollectionError {
                timestamp: "2026-05-16T00:00:00Z".to_string(),
                source: "trusted_proxy".to_string(),
                path: "10.0.0.0/8".to_string(),
                operation: "parse_cidr".to_string(),
                message: "trusted proxy CIDR could not be parsed".to_string(),
                detail: None,
            },
            CollectionError {
                timestamp: "2026-05-16T00:00:00Z".to_string(),
                source: "geoip".to_string(),
                path: "geo.csv".to_string(),
                operation: "parse".to_string(),
                message: "2 malformed GeoIP row(s) were skipped while loading".to_string(),
                detail: None,
            },
            CollectionError {
                timestamp: "2026-05-16T00:00:00Z".to_string(),
                source: "ioc".to_string(),
                path: "ioc.txt".to_string(),
                operation: "load".to_string(),
                message: "IOC file could not be loaded: value not found".to_string(),
                detail: None,
            },
        ];

        // 它们不出现在 gap 里,但错误对象本身(即 collection_errors.csv)仍保留。
        assert!(build_evidence_gaps(&resolved, &errors).is_empty());
    }
}
