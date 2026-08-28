use std::collections::BTreeMap;
use std::fs;

use crate::error::Result;
use crate::model::{DbLogEvent, Finding};
use crate::output::paths::OutputLayout;

pub fn write_suspicious_db_events(layout: &OutputLayout, findings: &[Finding]) -> Result<()> {
    let events = read_db_events(&layout.db_events)?;
    let by_hash = events
        .iter()
        .map(|event| (event.raw_hash.as_str(), event))
        .collect::<BTreeMap<_, _>>();

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&layout.suspicious_db_events)?;
    writer.write_record([
        "finding_id",
        "timestamp",
        "severity",
        "score",
        "category",
        "rule_id",
        "db_type",
        "db_user",
        "db_name",
        "client_ip",
        "statement_type",
        "statement_summary",
        "source_file",
        "line_number",
        "raw_hash",
        "recommendation",
    ])?;

    for finding in findings
        .iter()
        .filter(|finding| finding.source_type == "db_log")
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
                .map(|event| event.db_type.as_str())
                .unwrap_or_default(),
            event
                .and_then(|event| event.db_user.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.db_name.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.client_ip.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.statement_type.as_deref())
                .unwrap_or_default(),
            event
                .and_then(|event| event.statement_summary.as_deref())
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

fn read_db_events(path: &std::path::Path) -> Result<Vec<DbLogEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<DbLogEvent>(line) {
            events.push(event);
        }
    }
    Ok(events)
}
