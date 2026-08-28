use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::model::{Finding, Severity};
use crate::output::writers;

#[derive(Debug, Serialize)]
struct SarifLog {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifReportingDescriptor>,
}

#[derive(Debug, Serialize)]
struct SarifReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    help: SarifMessage,
    properties: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
    #[serde(rename = "relatedLocations", skip_serializing_if = "Vec::is_empty")]
    related_locations: Vec<SarifRelatedLocation>,
    properties: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifRelatedLocation {
    id: usize,
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
    message: SarifMessage,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u64,
}

pub fn write_sarif_report(path: &Path, findings: &[Finding]) -> Result<()> {
    let rules = build_rules(findings);
    let results = findings.iter().map(result_from_finding).collect();
    let mut properties = BTreeMap::new();
    properties.insert(
        "offline".to_string(),
        serde_json::Value::String("true".to_string()),
    );
    properties.insert(
        "interpretation".to_string(),
        serde_json::Value::String(
            "Findings are suspicious evidence for manual review, not proof of compromise."
                .to_string(),
        ),
    );

    let log = SarifLog {
        version: "2.1.0",
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "dumpall",
                    semantic_version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://example.invalid/dumpall/offline",
                    rules,
                },
            },
            results,
            properties,
        }],
    };
    writers::write_json_pretty(path, &log)
}

fn build_rules(findings: &[Finding]) -> Vec<SarifReportingDescriptor> {
    let mut by_rule = BTreeMap::<String, &Finding>::new();
    for finding in findings {
        by_rule.entry(finding.rule_id.clone()).or_insert(finding);
    }
    by_rule
        .into_values()
        .map(|finding| {
            let mut properties = BTreeMap::new();
            properties.insert(
                "category".to_string(),
                serde_json::Value::String(finding.category.clone()),
            );
            properties.insert(
                "sourceType".to_string(),
                serde_json::Value::String(finding.source_type.clone()),
            );
            SarifReportingDescriptor {
                id: finding.rule_id.clone(),
                name: finding.rule_name.clone(),
                short_description: SarifMessage {
                    text: finding.rule_name.clone(),
                },
                help: SarifMessage {
                    text: finding.recommendation.clone(),
                },
                properties,
            }
        })
        .collect()
}

fn result_from_finding(finding: &Finding) -> SarifResult {
    let mut properties = BTreeMap::new();
    properties.insert(
        "findingId".to_string(),
        serde_json::Value::String(finding.finding_id.clone()),
    );
    properties.insert(
        "score".to_string(),
        serde_json::Value::Number(serde_json::Number::from(finding.score)),
    );
    properties.insert(
        "category".to_string(),
        serde_json::Value::String(finding.category.clone()),
    );
    properties.insert(
        "confidence".to_string(),
        serde_json::Value::String(finding.confidence.as_str().to_string()),
    );
    properties.insert(
        "evidenceQuality".to_string(),
        serde_json::Value::String(finding.evidence_quality.as_str().to_string()),
    );
    if !finding.evidence_quality_basis.is_empty() {
        properties.insert(
            "evidenceQualityBasis".to_string(),
            serde_json::Value::String(finding.evidence_quality_basis.clone()),
        );
    }
    properties.insert(
        "sourceType".to_string(),
        serde_json::Value::String(finding.source_type.clone()),
    );
    if let Some(raw_hash) = &finding.raw_hash {
        properties.insert(
            "rawHash".to_string(),
            serde_json::Value::String(raw_hash.clone()),
        );
    }
    if let Some(level) = &finding.evidence_chain_level {
        properties.insert(
            "evidenceChainLevel".to_string(),
            serde_json::Value::String(level.clone()),
        );
    }
    if let Some(basis) = &finding.evidence_chain_basis {
        properties.insert(
            "evidenceChainBasis".to_string(),
            serde_json::Value::String(basis.clone()),
        );
    }
    if !finding.related_ids.is_empty() {
        properties.insert(
            "relatedFindingIds".to_string(),
            serde_json::Value::Array(
                finding
                    .related_ids
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }

    SarifResult {
        rule_id: finding.rule_id.clone(),
        level: sarif_level(finding.severity),
        message: SarifMessage {
            text: finding.evidence_summary.clone(),
        },
        locations: location_from_finding(finding)
            .map(|location| vec![location])
            .unwrap_or_default(),
        related_locations: related_locations_from_finding(finding),
        properties,
    }
}

fn location_from_finding(finding: &Finding) -> Option<SarifLocation> {
    let source_file = finding.source_file.as_deref()?.trim();
    if source_file.is_empty() {
        return None;
    }
    Some(SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: sanitize_uri(source_file),
            },
            region: finding
                .line_number
                .filter(|line| *line > 0)
                .map(|line| SarifRegion { start_line: line }),
        },
    })
}

fn related_locations_from_finding(finding: &Finding) -> Vec<SarifRelatedLocation> {
    finding
        .related_ids
        .iter()
        .take(10)
        .enumerate()
        .map(|(index, related_id)| SarifRelatedLocation {
            id: index + 1,
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding
                        .source_file
                        .as_deref()
                        .map(sanitize_uri)
                        .unwrap_or_else(|| "unknown".to_string()),
                },
                region: None,
            },
            message: SarifMessage {
                text: format!("Related finding {related_id}"),
            },
        })
        .collect()
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn sanitize_uri(value: &str) -> String {
    value.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::model::Severity;

    use super::*;

    #[test]
    fn sarif_maps_finding_core_fields() {
        let root = crate::unique_test_dir("sarif");
        fs::create_dir_all(&root).unwrap();
        let output = root.join("dumpall.sarif");
        let finding = Finding {
            finding_id: "F-000001".to_string(),
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            severity: Severity::High,
            score: 80,
            confidence: crate::model::Confidence::Medium,
            evidence_quality: crate::model::EvidenceQuality::Q2,
            evidence_quality_basis: "strong correlation".to_string(),
            score_breakdown: crate::model::ScoreBreakdown::from_final_score(80),
            category: "sqli".to_string(),
            rule_id: "WEB-SQLI-001".to_string(),
            rule_name: "SQL injection structure".to_string(),
            source_type: "access_log".to_string(),
            source_file: Some(r"C:\logs\access.log".to_string()),
            line_number: Some(42),
            remote_ip: Some("203.0.113.10".to_string()),
            method: Some("GET".to_string()),
            uri_path: Some("/search".to_string()),
            status: Some(200),
            evidence_summary: "Suspicious SQLi evidence with hash only.".to_string(),
            raw_hash: Some("abc123".to_string()),
            related_ids: vec!["F-000002".to_string()],
            evidence_chain_level: Some("L3".to_string()),
            evidence_chain_basis: Some("cross-log correlation".to_string()),
            recommendation: "Review adjacent evidence.".to_string(),
        };

        write_sarif_report(&output, &[finding]).unwrap();

        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "WEB-SQLI-001");
        assert_eq!(value["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            value["runs"][0]["results"][0]["properties"]["evidenceQuality"],
            "Q2"
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            42
        );

        fs::remove_dir_all(root).unwrap();
    }
}
