pub mod geoip;
pub mod identity;
pub mod ioc;
pub mod trusted_proxy;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::collectors::collection_error;
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{CollectionError, DbLogEvent, Finding, HttpLogEvent};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use geoip::GeoIpDb;
use identity::{classify_ip_text, IpType};

#[derive(Debug, Default)]
pub struct EnrichmentReport {
    pub ip_rows: usize,
    pub ioc_matches: usize,
    pub proxy_inferences: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<CollectionError>,
}

#[derive(Debug, Default)]
struct IpStats {
    ip_type: IpType,
    first_seen: Option<String>,
    last_seen: Option<String>,
    first_seen_nanos: Option<i128>,
    last_seen_nanos: Option<i128>,
    request_count: u64,
    finding_count: u64,
    max_score: u16,
    sources: BTreeSet<String>,
    client_ip_sources: BTreeSet<String>,
    proxy_ips: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
struct IpEnrichmentRow {
    ip: String,
    ip_type: String,
    country: String,
    region: String,
    city: String,
    asn: String,
    as_org: String,
    is_internal: bool,
    first_seen: String,
    last_seen: String,
    request_count: u64,
    // 列名沿用 finding_count,但它只统计 IOC 命中 finding(detector 产生的
    // finding 不在本模块统计),解读该列时按 ioc_finding_count 理解。
    finding_count: u64,
    max_score: u16,
    sources: String,
    client_ip_source: String,
    proxy_ips: String,
}

#[derive(Debug, Serialize)]
struct GeoSummaryRow {
    country: String,
    ip_count: usize,
    request_count: u64,
    // 同 IpEnrichmentRow::finding_count:仅统计 IOC 命中。
    finding_count: u64,
    max_score: u16,
}

#[derive(Debug, Serialize)]
struct AsnSummaryRow {
    asn: String,
    as_org: String,
    ip_count: usize,
    request_count: u64,
    // 同 IpEnrichmentRow::finding_count:仅统计 IOC 命中。
    finding_count: u64,
    max_score: u16,
}

pub fn run_enrichment(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<EnrichmentReport> {
    let mut report = EnrichmentReport::default();

    let (proxy_report, skipped_proxy_lines) = apply_trusted_proxy(resolved, layout)?;
    for invalid in proxy_report.invalid_entries {
        report.errors.push(collection_error(
            "trusted_proxy",
            invalid,
            "parse_cidr",
            "trusted proxy CIDR could not be parsed",
            None,
        ));
    }
    report.proxy_inferences = proxy_report.inferences;

    let ioc_report = ioc::run_ioc_matching(&resolved.ioc, layout)?;
    report.ioc_matches = ioc_report.matches;
    report.errors.extend(ioc_report.errors);
    report.findings.extend(ioc_report.findings);

    let (geoip, geoip_errors) = GeoIpDb::load(resolved.geoip_db.as_deref());
    report.errors.extend(geoip_errors);
    let (ip_rows, skipped_input_lines) = write_ip_outputs(layout, &geoip, &report.findings)?;
    report.ip_rows = ip_rows;

    let mut skipped_sources = Vec::new();
    if skipped_proxy_lines > 0 {
        skipped_sources.push((layout.http_events.clone(), skipped_proxy_lines));
    }
    skipped_sources.extend(skipped_input_lines);
    if !skipped_sources.is_empty() {
        let summary = skipped_sources
            .iter()
            .map(|(path, count)| format!("{} line(s) in {}", count, path.display()))
            .collect::<Vec<_>>()
            .join("; ");
        report.errors.push(collection_error(
            "enrich",
            layout.root.display().to_string(),
            "parse",
            format!("malformed JSONL evidence line(s) were skipped during enrichment: {summary}"),
            None,
        ));
    }

    logger.log(format!(
        "enrich: {} IP enrichment row(s), {} IOC match(es), {} proxy inference(s)",
        report.ip_rows, report.ioc_matches, report.proxy_inferences
    ))?;
    Ok(report)
}

fn apply_trusted_proxy(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
) -> Result<(trusted_proxy::TrustedProxyReport, usize)> {
    let (mut events, skipped_lines) = read_jsonl::<HttpLogEvent>(&layout.http_events)?;
    let report = trusted_proxy::apply_trusted_proxy(&mut events, &resolved.trusted_proxy);
    if report.inferences > 0 {
        writers::write_http_events_jsonl(&layout.http_events, &events)?;
    }
    Ok((report, skipped_lines))
}

fn write_ip_outputs(
    layout: &OutputLayout,
    geoip: &GeoIpDb,
    enrichment_findings: &[Finding],
) -> Result<(usize, Vec<(std::path::PathBuf, usize)>)> {
    let (http_events, skipped_http) = read_jsonl::<HttpLogEvent>(&layout.http_events)?;
    let (db_events, skipped_db) = read_jsonl::<DbLogEvent>(&layout.db_events)?;
    let mut stats = BTreeMap::<String, IpStats>::new();
    let mut skipped_lines = Vec::new();
    if skipped_http > 0 {
        skipped_lines.push((layout.http_events.clone(), skipped_http));
    }
    if skipped_db > 0 {
        skipped_lines.push((layout.db_events.clone(), skipped_db));
    }

    for event in &http_events {
        if let Some(ip) = event.effective_remote_ip() {
            let row = stats.entry(ip.to_string()).or_insert_with(|| IpStats {
                ip_type: classify_ip_text(ip),
                ..IpStats::default()
            });
            row.request_count += 1;
            row.sources.insert("http".to_string());
            if let Some(timestamp) = event.timestamp.as_deref() {
                update_seen(row, timestamp);
            }
            if let Some(source) = event.client_ip_source.as_deref() {
                row.client_ip_sources.insert(source.to_string());
            }
            if let Some(proxy_ip) = event.proxy_ip.as_deref() {
                row.proxy_ips.insert(proxy_ip.to_string());
            }
        }
    }

    for event in &db_events {
        if let Some(ip) = event.client_ip.as_deref().filter(|value| !value.is_empty()) {
            let row = stats.entry(ip.to_string()).or_insert_with(|| IpStats {
                ip_type: classify_ip_text(ip),
                ..IpStats::default()
            });
            row.sources.insert("db".to_string());
            if let Some(timestamp) = event.timestamp.as_deref() {
                update_seen(row, timestamp);
            }
        }
    }

    for finding in enrichment_findings {
        if let Some(ip) = finding
            .remote_ip
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let row = stats.entry(ip.to_string()).or_insert_with(|| IpStats {
                ip_type: classify_ip_text(ip),
                ..IpStats::default()
            });
            row.sources.insert("ioc".to_string());
            row.finding_count += 1;
            row.max_score = row.max_score.max(finding.score);
            if let Some(timestamp) = finding.timestamp.as_deref() {
                update_seen(row, timestamp);
            }
        }
    }

    let rows = stats
        .iter()
        .map(|(ip, stat)| {
            let lookup = geoip.lookup(ip).unwrap_or_default();
            IpEnrichmentRow {
                ip: ip.clone(),
                ip_type: stat.ip_type.as_str().to_string(),
                country: lookup.country,
                region: lookup.region,
                city: lookup.city,
                asn: lookup.asn,
                as_org: lookup.as_org,
                is_internal: stat.ip_type.is_internal(),
                first_seen: stat.first_seen.clone().unwrap_or_default(),
                last_seen: stat.last_seen.clone().unwrap_or_default(),
                request_count: stat.request_count,
                finding_count: stat.finding_count,
                max_score: stat.max_score,
                sources: join_set(&stat.sources),
                client_ip_source: join_set(&stat.client_ip_sources),
                proxy_ips: join_set(&stat.proxy_ips),
            }
        })
        .collect::<Vec<_>>();

    write_ip_enrichment(&layout.ip_enrichment, &rows)?;
    write_geo_summary(&layout.geoip_summary, &rows)?;
    write_asn_summary(&layout.asn_summary, &rows)?;
    Ok((rows.len(), skipped_lines))
}

fn update_seen(stats: &mut IpStats, timestamp: &str) {
    // 用解析后的绝对时刻比较并保留原字符串:混合 +08:00 与 Z 偏移时,
    // ISO 字符串字典序与真实时间序不一致。
    let Some(nanos) = crate::time_utils::timestamp_instant_nanos(Some(timestamp)) else {
        return;
    };
    if stats
        .first_seen_nanos
        .map(|seen| nanos < seen)
        .unwrap_or(true)
    {
        stats.first_seen_nanos = Some(nanos);
        stats.first_seen = Some(timestamp.to_string());
    }
    if stats.last_seen_nanos.map(|seen| nanos > seen).unwrap_or(true) {
        stats.last_seen_nanos = Some(nanos);
        stats.last_seen = Some(timestamp.to_string());
    }
}

fn write_ip_enrichment(path: &Path, rows: &[IpEnrichmentRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(
            path,
            "ip,ip_type,country,region,city,asn,as_org,is_internal,first_seen,last_seen,request_count,finding_count,max_score,sources,client_ip_source,proxy_ips\n",
        )
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

fn write_geo_summary(path: &Path, rows: &[IpEnrichmentRow]) -> Result<()> {
    let mut groups: BTreeMap<String, GeoSummaryRow> = BTreeMap::new();
    for row in rows {
        let country = if row.country.is_empty() {
            "unknown".to_string()
        } else {
            row.country.clone()
        };
        let entry = groups.entry(country.clone()).or_insert(GeoSummaryRow {
            country,
            ip_count: 0,
            request_count: 0,
            finding_count: 0,
            max_score: 0,
        });
        entry.ip_count += 1;
        entry.request_count += row.request_count;
        entry.finding_count += row.finding_count;
        entry.max_score = entry.max_score.max(row.max_score);
    }
    let rows = groups.into_values().collect::<Vec<_>>();
    if rows.is_empty() {
        writers::write_text(
            path,
            "country,ip_count,request_count,finding_count,max_score\n",
        )
    } else {
        writers::write_csv_serialize(path, &rows)
    }
}

fn write_asn_summary(path: &Path, rows: &[IpEnrichmentRow]) -> Result<()> {
    let mut groups: BTreeMap<(String, String), AsnSummaryRow> = BTreeMap::new();
    for row in rows {
        let asn = if row.asn.is_empty() {
            "unknown".to_string()
        } else {
            row.asn.clone()
        };
        let as_org = row.as_org.clone();
        let entry = groups
            .entry((asn.clone(), as_org.clone()))
            .or_insert(AsnSummaryRow {
                asn,
                as_org,
                ip_count: 0,
                request_count: 0,
                finding_count: 0,
                max_score: 0,
            });
        entry.ip_count += 1;
        entry.request_count += row.request_count;
        entry.finding_count += row.finding_count;
        entry.max_score = entry.max_score.max(row.max_score);
    }
    let rows = groups.into_values().collect::<Vec<_>>();
    if rows.is_empty() {
        writers::write_text(
            path,
            "asn,as_org,ip_count,request_count,finding_count,max_score\n",
        )
    } else {
        writers::write_csv_serialize(path, &rows)
    }
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<(Vec<T>, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }
    let content = fs::read_to_string(path)?;
    // 坏行不再被静默丢弃:计数返回,由调用方写入报告告警。
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<T>(line) {
            Ok(row) => rows.push(row),
            Err(_) => skipped += 1,
        }
    }
    Ok((rows, skipped))
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(";")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::paths::OutputLayout;

    #[test]
    fn enrichment_writes_proxy_inferred_ip_row() {
        let root = crate::unique_test_dir("enrich");
        let layout = OutputLayout::create(root.join("results")).unwrap();
        writers::initialize_required_files(&layout).unwrap();
        writers::write_http_events_jsonl(
            &layout.http_events,
            &[HttpLogEvent {
                timestamp: Some("2026-05-15T00:00:00Z".to_string()),
                source_file: "access.log".to_string(),
                line_number: 1,
                remote_ip: Some("10.0.0.5".to_string()),
                xff_ip: Some("198.51.100.7, 10.0.0.5".to_string()),
                inferred_client_ip: None,
                proxy_ip: None,
                client_ip_source: None,
                method: Some("GET".to_string()),
                scheme: None,
                host: None,
                uri_path: Some("/".to_string()),
                uri_query: None,
                status: Some(200),
                bytes_sent: None,
                referer: None,
                user_agent: None,
                request_time: None,
                upstream_status: None,
                upstream_time: None,
                raw_hash: "hash".to_string(),
                parser_name: "fixture".to_string(),
                parse_confidence: 1.0,
            }],
        )
        .unwrap();

        let resolved = crate::config::ResolvedRun {
            mode: crate::model::RunMode::Analyze,
            started_at: "2026-05-15T00:00:00Z".to_string(),
            time_range: crate::model::TimeRange {
                mode: "recent_hours".to_string(),
                since: None,
                until: None,
                hours: Some(5),
            },
            updatetime: false,
            web_paths: Vec::new(),
            log_paths: Vec::new(),
            db_type: crate::model::DbType::Auto,
            db_log_paths: Vec::new(),
            waf_log_paths: Vec::new(),
            app_log_paths: Vec::new(),
            middleware: None,
            profile: crate::profile::ScanProfile::Quick,
            timeline: false,
            sarif: false,
            baseline: None,
            static_scan: false,
            yara_rules: Vec::new(),
            trusted_proxy: vec!["10.0.0.0/8".to_string()],
            geoip_db: None,
            ioc: Vec::new(),
            runtime_scan: false,
            runtime_target: crate::model::RuntimeTarget::Auto,
            java_home: None,
            tomcat_base: Vec::new(),
            spring_app_path: Vec::new(),
            iis_config: None,
            evtx_paths: Vec::new(),
            journal_paths: Vec::new(),
            audit_log_paths: Vec::new(),
            container_runtime: crate::model::ContainerRuntime::Auto,
            container_log_paths: Vec::new(),
            k8s_node_paths: Vec::new(),
            evidence_pack: false,
            pack_format: crate::model::PackFormat::Zip,
            component_baseline: None,
            runtime_active_check: false,
            max_event_records: 200_000,
            output_dir: layout.root.clone(),
            formats: vec![crate::model::OutputFormat::Jsonl],
            full_scan: false,
            max_static_file_size_mb: 10,
            max_yara_file_size_mb: 20,
            safety: crate::safety::SafetyLimits {
                max_cpu_percent: 50,
                threads: 1,
                max_file_size_mb: 512,
                max_depth: 4,
                redact: false,
                offline: true,
                verbose: false,
            },
            rules: Vec::new(),
            allowlist: None,
            memory_tool: None,
            memory_dump: false,
            memory_triage: false,
            copy_raw: false,
            xlsx_report: false,
            log_days: 30,
            event_cutoff: None,
        };
        let mut logger = writers::RunLogger::create(&layout.run_log, false).unwrap();

        let report = run_enrichment(&resolved, &layout, &mut logger).unwrap();

        assert_eq!(report.proxy_inferences, 1);
        let rows = fs::read_to_string(&layout.ip_enrichment).unwrap();
        assert!(rows.contains("198.51.100.7"));
        assert!(rows.contains("trusted_proxy_header"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_seen_orders_mixed_offsets_by_instant() {
        // 09:30+08:00=01:30Z 最早,05:00Z 次之,21:00+08:00=13:00Z 最晚;
        // ISO 字符串字典序会得出完全相反的结论。
        let mut stats = IpStats::default();
        update_seen(&mut stats, "2026-08-27T21:00:00+08:00");
        update_seen(&mut stats, "2026-08-27T05:00:00Z");
        update_seen(&mut stats, "2026-08-27T09:30:00+08:00");

        assert_eq!(
            stats.first_seen.as_deref(),
            Some("2026-08-27T09:30:00+08:00")
        );
        assert_eq!(stats.last_seen.as_deref(), Some("2026-08-27T21:00:00+08:00"));

        // 不可解析时间戳不参与 first/last_seen。
        let mut garbage = IpStats::default();
        update_seen(&mut garbage, "not-a-timestamp");
        assert!(garbage.first_seen.is_none());
        assert!(garbage.last_seen.is_none());
    }
}
