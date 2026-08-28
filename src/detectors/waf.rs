use std::collections::BTreeMap;
use std::fs;

use crate::error::Result;
use crate::model::{Finding, WafLogEvent};
use crate::output::paths::OutputLayout;

pub fn write_suspicious_waf_events(layout: &OutputLayout, findings: &[Finding]) -> Result<()> {
    let events = read_waf_events(&layout.waf_events)?;
    let by_hash = events
        .iter()
        .map(|event| (event.raw_hash.as_str(), event))
        .collect::<BTreeMap<_, _>>();

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&layout.suspicious_waf_events)?;
    writer.write_record([
        "finding_id",
        "timestamp",
        "severity",
        "score",
        "category",
        "rule_id",
        "vendor",
        "action",
        "waf_rule_id",
        "waf_rule_name",
        "client_ip",
        "proxy_ip",
        "host",
        "method",
        "path",
        "status",
        "waf_score",
        "source_file",
        "line_number",
        "raw_hash",
        "recommendation",
    ])?;

    for finding in findings
        .iter()
        .filter(|finding| finding.source_type == "waf_log")
    {
        let event = finding
            .raw_hash
            .as_deref()
            .and_then(|hash| by_hash.get(hash).copied());
        writer.write_record([
            finding.finding_id.as_str(),
            finding.timestamp.as_deref().unwrap_or_default(),
            finding.severity.as_str(),
            &finding.score.to_string(),
            finding.category.as_str(),
            finding.rule_id.as_str(),
            event
                .and_then(|event| event.vendor.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.action.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.rule_id.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.rule_name.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.client_ip.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.proxy_ip.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.host.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.method.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.path.as_deref())
                .unwrap_or_default(),
            &event
                .and_then(|event| event.status)
                .map(|status| status.to_string())
                .unwrap_or_default(),
            &event
                .and_then(|event| event.score)
                .map(|score| score.to_string())
                .unwrap_or_default(),
            finding.source_file.as_deref().unwrap_or_default(),
            &finding
                .line_number
                .map(|line| line.to_string())
                .unwrap_or_default(),
            finding.raw_hash.as_deref().unwrap_or_default(),
            finding.recommendation.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn read_waf_events(path: &std::path::Path) -> Result<Vec<WafLogEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<WafLogEvent>(line) {
            events.push(event);
        }
    }
    Ok(events)
}
