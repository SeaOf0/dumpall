use std::collections::BTreeMap;
use std::fs;

use crate::error::Result;
use crate::model::{AppLogEvent, Finding};
use crate::output::paths::OutputLayout;

pub fn write_suspicious_app_events(layout: &OutputLayout, findings: &[Finding]) -> Result<()> {
    let events = read_app_events(&layout.app_events)?;
    let by_hash = events
        .iter()
        .map(|event| (event.raw_hash.as_str(), event))
        .collect::<BTreeMap<_, _>>();

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&layout.suspicious_app_events)?;
    writer.write_record([
        "finding_id",
        "timestamp",
        "severity",
        "score",
        "category",
        "rule_id",
        "framework",
        "level",
        "exception_type",
        "http_path",
        "trace_id",
        "request_id",
        "message_summary",
        "source_file",
        "line_number",
        "raw_hash",
        "recommendation",
    ])?;

    for finding in findings
        .iter()
        .filter(|finding| finding.source_type == "app_log")
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
                .and_then(|event| event.framework.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.level.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.exception_type.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.http_path.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.trace_id.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.request_id.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.message_summary.as_deref())
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

fn read_app_events(path: &std::path::Path) -> Result<Vec<AppLogEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<AppLogEvent>(line) {
            events.push(event);
        }
    }
    Ok(events)
}
