use std::path::Path;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{EvidenceQuality, Finding, ScoreBreakdown, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};
use crate::report::zh;

pub const RULE_CATEGORY: &str = "runtime_component";

#[derive(Debug, Default)]
pub struct RuntimeDetectionReport {
    pub findings: Vec<Finding>,
    pub rows_seen: usize,
}

#[derive(Debug)]
struct RuntimeRow {
    component_id: String,
    component_type: String,
    name: String,
    class_name: String,
    route_or_pattern: String,
    source_file: String,
    source_path: String,
    declared_in: String,
    mtime: String,
    sha256: String,
    is_recent: bool,
    is_baseline_new: bool,
    risk_flags: String,
    confidence: String,
    runtime_type: String,
    source_table: &'static str,
    line_number: u64,
}

pub fn run_runtime_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<RuntimeDetectionReport> {
    if !resolved.runtime_scan_enabled() {
        return Ok(RuntimeDetectionReport::default());
    }

    let mut rows = Vec::new();
    rows.extend(read_tomcat_components(&layout.tomcat_components)?);
    rows.extend(read_java_components(&layout.java_components)?);
    rows.extend(read_spring_mappings(&layout.spring_mappings)?);
    rows.extend(read_iis_modules(&layout.iis_modules)?);
    rows.extend(read_aspnet_handlers(&layout.aspnet_handlers)?);
    logger.log(format!(
        "detector: runtime component inventory has {} row(s)",
        rows.len()
    ))?;

    let mut findings = Vec::new();
    for row in &rows {
        if let Some(finding) = finding_from_row(row, findings.len() + 1) {
            findings.push(finding);
        }
    }
    write_runtime_report(&layout.runtime_report, &rows, &findings)?;
    Ok(RuntimeDetectionReport {
        findings,
        rows_seen: rows.len(),
    })
}

fn finding_from_row(row: &RuntimeRow, index: usize) -> Option<Finding> {
    let flags = row
        .risk_flags
        .split(';')
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    if flags.is_empty() {
        return None;
    }

    let mut score = 25_u16;
    for flag in &flags {
        score = score.saturating_add(match *flag {
            "broad_mapping" => 30,
            "suspicious_name" | "suspicious_class" => 25,
            "baseline_new" => 20,
            "recent_change" => 15,
            "management_endpoint_exposure" => 25,
            "handler_script_processor" => 25,
            "privileged_app_pool_identity" => 25,
            "work_temp_artifact" => 15,
            "webapps_artifact" | "static_archive_component" => 10,
            "global_module" | "site_module" | "site_handler" | "global_handler" => 10,
            "bin_dll" | "native_image_path" | "web_config_change" | "fastcgi" => 10,
            "unknown_signature" => 5,
            "log_mapping_hint" => 5,
            "unusual_runtime_config" => 10,
            _ => 5,
        });
    }
    score = score.min(100);
    if score < 45 {
        return None;
    }

    let (category, rule_id, rule_name) = match row.runtime_type.as_str() {
        "spring" => (
            "runtime_spring_mapping",
            "RUNTIME-SPRING-MAPPING-001",
            "Spring runtime mapping or component inventory risk",
        ),
        "iis" | "aspnet" => (
            "runtime_iis_module",
            "RUNTIME-IIS-MODULE-001",
            "IIS/ASP.NET runtime component inventory risk",
        ),
        _ => (
            "runtime_java_component",
            "RUNTIME-JAVA-COMPONENT-001",
            "Java/Tomcat runtime component inventory risk",
        ),
    };
    // 评分拆分只在专用字段记一次（runtime_score），不再 from_base 同值双记。
    let mut breakdown = ScoreBreakdown::default();
    breakdown.runtime_score = score as i16;
    let route = (!row.route_or_pattern.is_empty()).then(|| row.route_or_pattern.clone());

    let evidence = format!(
        "Runtime inventory row {} from {} recorded {} {} {} in {} with flags {}{}{}. Treat as suspicious component evidence, not proof of an in-memory implant.",
        row.component_id,
        row.source_table,
        row.runtime_type,
        row.component_type,
        preferred_name(row),
        if row.declared_in.is_empty() { "unspecified scope" } else { row.declared_in.as_str() },
        row.risk_flags,
        if row.is_recent { "; recent_change=true" } else { "" },
        if row.is_baseline_new { "; baseline_new=true" } else { "" }
    );

    Some(Finding {
        finding_id: format!("RT-F-{index:06}"),
        timestamp: (row.mtime != "unknown").then(|| row.mtime.clone()),
        severity: Severity::from_score(score),
        score,
        confidence: crate::model::confidence_for(score, EvidenceQuality::Q1),
        evidence_quality: EvidenceQuality::Q1,
        evidence_quality_basis:
            "Q1 direct runtime component evidence from static configuration, deployment metadata, or file hash".to_string(),
        score_breakdown: breakdown,
        category: category.to_string(),
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        source_type: "runtime".to_string(),
        source_file: Some(row.source_file.clone()),
        line_number: Some(row.line_number),
        remote_ip: None,
        method: None,
        uri_path: route,
        status: None,
        evidence_summary: evidence,
        raw_hash: (!row.sha256.is_empty()).then(|| row.sha256.clone()),
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: "Review deployment history, source ownership, component baseline, adjacent HTTP/application logs, and process evidence before drawing conclusions.".to_string(),
    })
}

fn read_tomcat_components(path: &Path) -> Result<Vec<RuntimeRow>> {
    read_csv_rows(path, "tomcat_components", |line_number, get| RuntimeRow {
        component_id: get("component_id"),
        runtime_type: get("runtime_type"),
        component_type: get("component_type"),
        name: get("name"),
        class_name: get("class_name"),
        route_or_pattern: get("url_pattern"),
        source_file: get("source_file"),
        source_path: get("source_path"),
        declared_in: get("declared_in"),
        mtime: get("mtime"),
        sha256: get("sha256"),
        is_recent: parse_bool(&get("is_recent")),
        is_baseline_new: parse_bool(&get("is_baseline_new")),
        risk_flags: get("risk_flags"),
        confidence: get("confidence"),
        source_table: "runtime/tomcat_components.csv",
        line_number,
    })
}

fn read_java_components(path: &Path) -> Result<Vec<RuntimeRow>> {
    read_csv_rows(path, "java_components", |line_number, get| RuntimeRow {
        component_id: get("component_id"),
        runtime_type: get("runtime_type"),
        component_type: get("component_type"),
        name: get("name"),
        class_name: get("class_name"),
        route_or_pattern: String::new(),
        source_file: get("source_file"),
        source_path: get("source_path"),
        declared_in: get("declared_in"),
        mtime: get("mtime"),
        sha256: get("sha256"),
        is_recent: parse_bool(&get("is_recent")),
        is_baseline_new: parse_bool(&get("is_baseline_new")),
        risk_flags: get("risk_flags"),
        confidence: get("confidence"),
        source_table: "runtime/java_components.csv",
        line_number,
    })
}

fn read_spring_mappings(path: &Path) -> Result<Vec<RuntimeRow>> {
    read_csv_rows(path, "spring_mappings", |line_number, get| RuntimeRow {
        component_id: get("component_id"),
        runtime_type: "spring".to_string(),
        component_type: get("component_type"),
        name: get("route"),
        class_name: get("class_name"),
        route_or_pattern: get("route"),
        source_file: get("jar_path"),
        source_path: get("jar_path"),
        declared_in: get("source"),
        mtime: get("mtime"),
        sha256: get("sha256"),
        is_recent: false,
        is_baseline_new: get("risk_flags").contains("baseline_new"),
        risk_flags: get("risk_flags"),
        confidence: get("confidence"),
        source_table: "runtime/spring_mappings.csv",
        line_number,
    })
}

fn read_iis_modules(path: &Path) -> Result<Vec<RuntimeRow>> {
    read_csv_rows(path, "iis_modules", |line_number, get| RuntimeRow {
        component_id: get("component_id"),
        runtime_type: "iis".to_string(),
        component_type: get("component_type"),
        name: get("name"),
        class_name: get("precondition"),
        route_or_pattern: String::new(),
        source_file: first_non_empty(&[get("source_config"), get("path")]),
        source_path: get("path"),
        declared_in: declared_scope(&get("site_name"), &get("app_pool")),
        mtime: get("mtime"),
        sha256: get("sha256"),
        is_recent: parse_bool(&get("is_recent")),
        is_baseline_new: parse_bool(&get("is_baseline_new")),
        risk_flags: get("risk_flags"),
        confidence: get("confidence"),
        source_table: "runtime/iis_modules.csv",
        line_number,
    })
}

fn read_aspnet_handlers(path: &Path) -> Result<Vec<RuntimeRow>> {
    read_csv_rows(path, "aspnet_handlers", |line_number, get| RuntimeRow {
        component_id: get("component_id"),
        runtime_type: "aspnet".to_string(),
        component_type: get("component_type"),
        name: get("name"),
        class_name: get("resource_type"),
        route_or_pattern: get("path"),
        source_file: get("source_config"),
        source_path: get("path"),
        declared_in: declared_scope(&get("site_name"), &get("app_pool")),
        mtime: get("mtime"),
        sha256: get("sha256"),
        is_recent: false,
        is_baseline_new: get("risk_flags").contains("baseline_new"),
        risk_flags: get("risk_flags"),
        confidence: get("confidence"),
        source_table: "runtime/aspnet_handlers.csv",
        line_number,
    })
}

fn read_csv_rows<F>(path: &Path, table_name: &'static str, mut build: F) -> Result<Vec<RuntimeRow>>
where
    F: FnMut(u64, &dyn Fn(&str) -> String) -> RuntimeRow,
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
        let row = build(index as u64 + 2, &get);
        if row.component_id.is_empty()
            && row.component_type.is_empty()
            && row.name.is_empty()
            && row.class_name.is_empty()
        {
            continue;
        }
        let mut row = row;
        if row.runtime_type.is_empty() {
            row.runtime_type = table_name.trim_end_matches("_components").to_string();
        }
        rows.push(row);
    }
    Ok(rows)
}

fn write_runtime_report(path: &Path, rows: &[RuntimeRow], findings: &[Finding]) -> Result<()> {
    let mut report = String::new();
    report.push_str("# 运行时组件报告\n\n");
    report.push_str(&format!("- 运行时清单行数：{}\n", rows.len()));
    report.push_str(&format!("- 运行时发现数：{}\n", findings.len()));
    report.push_str("- 主动运行时检查：默认关闭，除非显式请求；本报告基于静态、只读证据生成。\n\n");

    report.push_str("## 发现摘要\n\n");
    if findings.is_empty() {
        report.push_str("未产生运行时组件发现。\n\n");
    } else {
        for finding in findings.iter().take(20) {
            report.push_str(&format!(
                "- [{}] {} 分数 {} 证据质量 {} 来源 {}\n",
                zh::severity_label(finding.severity.as_str()),
                finding.rule_id,
                finding.score,
                zh::evidence_quality_label(finding.evidence_quality.as_str()),
                finding.source_file.as_deref().unwrap_or("无数据")
            ));
        }
        report.push('\n');
    }

    report.push_str("## 清单重点\n\n");
    if rows.is_empty() {
        report.push_str("未输出运行时清单行。\n");
    } else {
        for row in rows
            .iter()
            .filter(|row| !row.risk_flags.is_empty())
            .take(20)
        {
            report.push_str(&format!(
                "- {} {} {} 风险标记 {} 置信度 {}\n",
                row.runtime_type,
                row.component_type,
                preferred_name(row),
                row.risk_flags,
                zh::confidence_label(&row.confidence)
            ));
        }
    }
    writers::write_text(path, &report)
}

fn preferred_name(row: &RuntimeRow) -> &str {
    if !row.name.is_empty() {
        &row.name
    } else if !row.class_name.is_empty() {
        &row.class_name
    } else {
        &row.source_path
    }
}

fn declared_scope(site_name: &str, app_pool: &str) -> String {
    match (site_name.is_empty(), app_pool.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!("site={site_name}"),
        (true, false) => format!("app_pool={app_pool}"),
        (false, false) => format!("site={site_name}; app_pool={app_pool}"),
    }
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

fn normalize_header(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}
