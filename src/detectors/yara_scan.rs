#[cfg(feature = "yara")]
use std::fs;
use std::path::Path;
#[cfg(feature = "yara")]
use std::path::PathBuf;

use serde::Serialize;

use crate::collectors::collection_error;
use crate::config::ResolvedRun;
use crate::error::Result;
#[cfg(feature = "yara")]
use crate::model::Severity;
use crate::model::{CollectionError, Finding};
#[cfg(feature = "yara")]
use crate::model::{EvidenceQuality, ScoreBreakdown};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

#[cfg(feature = "yara")]
use super::static_scan::{
    collect_scan_candidates, file_extension, file_modified_iso, hash_bytes, ScanCandidate,
};

const YARA_MATCHES_HEADER: &str = "timestamp,file_path,file_sha256,file_size,mtime,rule_namespace,rule_name,rule_tags,match_count,matched_offsets_summary,score_delta,recommendation\n";

#[derive(Debug, Default)]
pub struct YaraScanReport {
    pub files_scanned: u64,
    pub rules_loaded: usize,
    pub matches: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<CollectionError>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct YaraMatchRow {
    timestamp: String,
    file_path: String,
    file_sha256: String,
    file_size: u64,
    mtime: String,
    rule_namespace: String,
    rule_name: String,
    rule_tags: String,
    match_count: usize,
    matched_offsets_summary: String,
    score_delta: u16,
    recommendation: String,
}

pub fn run_yara_scan(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<YaraScanReport> {
    run_yara_scan_impl(resolved, layout, logger)
}

#[cfg(not(feature = "yara"))]
fn run_yara_scan_impl(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<YaraScanReport> {
    write_yara_rows(&layout.yara_matches, &[])?;
    let mut report = YaraScanReport::default();
    let requested = resolved
        .yara_rules
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(";");
    report.errors.push(collection_error(
        "yara",
        requested,
        "initialize",
        "YARA support was requested but this binary was not compiled with the yara feature",
        Some("rebuild with --features yara or rerun without --yara-rules".to_string()),
    ));
    report.notes.push(
        "YARA rules were not evaluated because this build does not include the optional yara feature."
            .to_string(),
    );
    logger.log("yara: requested but optional yara feature is not compiled")?;
    Ok(report)
}

#[cfg(feature = "yara")]
fn run_yara_scan_impl(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<YaraScanReport> {
    let mut errors = Vec::new();
    let rules = load_lite_yara_rules(&resolved.yara_rules, &mut errors);
    let candidates = collect_scan_candidates(
        resolved,
        layout,
        resolved.max_yara_file_size_mb,
        "yara_scan",
        &mut errors,
    )?;
    logger.log(format!(
        "yara: lightweight literal adapter loaded {} rule(s), {} candidate file(s)",
        rules.len(),
        candidates.len()
    ))?;

    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for candidate in &candidates {
        let bytes = match fs::read(&candidate.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(collection_error(
                    "yara_scan",
                    candidate.path.display().to_string(),
                    "read_file",
                    "file could not be read for YARA inspection",
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        let file_hash = hash_bytes(&bytes);
        for rule in &rules {
            let offsets = rule.match_offsets(&bytes);
            if offsets.is_empty() {
                continue;
            }
            let mtime = file_modified_iso(candidate.modified);
            let row = YaraMatchRow {
                timestamp: crate::time_utils::now_iso(),
                file_path: candidate.path.display().to_string(),
                file_sha256: file_hash.clone(),
                file_size: candidate.size_bytes,
                mtime: mtime.clone(),
                rule_namespace: rule.namespace.clone(),
                rule_name: rule.name.clone(),
                rule_tags: rule.tags.join(";"),
                match_count: offsets.len(),
                matched_offsets_summary: offsets
                    .iter()
                    .take(8)
                    .map(|offset| format!("0x{offset:x}"))
                    .collect::<Vec<_>>()
                    .join(";"),
                score_delta: 20,
                recommendation: "Treat YARA output as supporting evidence and review surrounding Web, file, and host context before escalation.".to_string(),
            };
            findings.push(yara_finding(
                candidate,
                &file_hash,
                &mtime,
                rule,
                offsets.len(),
                findings.len() + 1,
            ));
            rows.push(row);
        }
    }

    write_yara_rows(&layout.yara_matches, &rows)?;
    let notes = vec![
        "YARA feature uses a dependency-light literal adapter in this build; complex YARA conditions are not interpreted."
            .to_string(),
    ];

    Ok(YaraScanReport {
        files_scanned: candidates.len() as u64,
        rules_loaded: rules.len(),
        matches: rows.len(),
        findings,
        errors,
        notes,
    })
}

fn write_yara_rows(path: &Path, rows: &[YaraMatchRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, YARA_MATCHES_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

#[cfg(feature = "yara")]
#[derive(Debug, Clone)]
struct LiteYaraRule {
    namespace: String,
    name: String,
    tags: Vec<String>,
    literals: Vec<YaraLiteral>,
}

#[cfg(feature = "yara")]
#[derive(Debug, Clone)]
struct YaraLiteral {
    value: Vec<u8>,
    nocase: bool,
}

#[cfg(feature = "yara")]
impl LiteYaraRule {
    fn match_offsets(&self, bytes: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        for literal in &self.literals {
            offsets.extend(find_literal_offsets(bytes, literal));
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

#[cfg(feature = "yara")]
fn load_lite_yara_rules(paths: &[PathBuf], errors: &mut Vec<CollectionError>) -> Vec<LiteYaraRule> {
    let mut files = Vec::new();
    for path in paths {
        expand_yara_rule_path(path, &mut files, errors);
    }
    files.sort();
    files.dedup();

    let mut rules = Vec::new();
    for file in files {
        let content = match fs::read_to_string(&file) {
            Ok(content) => content,
            Err(error) => {
                errors.push(collection_error(
                    "yara_scan",
                    file.display().to_string(),
                    "read_rules",
                    "YARA rule file could not be read",
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        let parsed = parse_lite_yara_rules(&file, &content);
        if parsed.is_empty() {
            errors.push(collection_error(
                "yara_scan",
                file.display().to_string(),
                "parse_rules",
                "no literal YARA strings were found by the lightweight adapter",
                None,
            ));
        }
        rules.extend(parsed);
    }
    rules
}

#[cfg(feature = "yara")]
fn expand_yara_rule_path(path: &Path, files: &mut Vec<PathBuf>, errors: &mut Vec<CollectionError>) {
    if path.is_file() {
        files.push(path.to_path_buf());
        return;
    }
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            errors.push(collection_error(
                "yara_scan",
                path.display().to_string(),
                "read_rules_dir",
                "YARA rule directory could not be read",
                None,
            ));
            return;
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            let is_yara = candidate
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| matches!(extension.to_ascii_lowercase().as_str(), "yar" | "yara"))
                .unwrap_or(false);
            if is_yara {
                files.push(candidate);
            }
        }
        return;
    }
    errors.push(collection_error(
        "yara_scan",
        path.display().to_string(),
        "read_rules",
        "YARA rule path does not exist",
        None,
    ));
}

#[cfg(feature = "yara")]
fn parse_lite_yara_rules(path: &Path, content: &str) -> Vec<LiteYaraRule> {
    let namespace = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("rules")
        .to_string();
    let mut rules = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_tags = Vec::new();
    let mut current_literals = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            if let Some(name) = current_name.take() {
                push_rule(
                    &mut rules,
                    &namespace,
                    name,
                    std::mem::take(&mut current_tags),
                    std::mem::take(&mut current_literals),
                );
            }
            let after_rule = trimmed.trim_start_matches("rule ").trim();
            let before_body = after_rule.split('{').next().unwrap_or(after_rule).trim();
            let mut pieces = before_body.split(':');
            current_name = pieces
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string);
            current_tags = pieces
                .next()
                .map(|tags| tags.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default();
            continue;
        }
        if current_name.is_some() && trimmed.contains('=') {
            for literal in extract_quoted_literals(trimmed) {
                current_literals.push(literal);
            }
        }
    }
    if let Some(name) = current_name {
        push_rule(&mut rules, &namespace, name, current_tags, current_literals);
    }
    rules
}

#[cfg(feature = "yara")]
fn push_rule(
    rules: &mut Vec<LiteYaraRule>,
    namespace: &str,
    name: String,
    tags: Vec<String>,
    literals: Vec<YaraLiteral>,
) {
    if literals.is_empty() {
        return;
    }
    rules.push(LiteYaraRule {
        namespace: namespace.to_string(),
        name,
        tags,
        literals,
    });
}

#[cfg(feature = "yara")]
fn extract_quoted_literals(line: &str) -> Vec<YaraLiteral> {
    let mut literals = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        let mut end_index = start + ch.len_utf8();
        for (index, ch) in chars.by_ref() {
            end_index = index + ch.len_utf8();
            if escaped {
                value.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                break;
            }
            value.push(ch);
        }
        if !value.is_empty() {
            let modifiers = &line[end_index..];
            literals.push(YaraLiteral {
                value: value.into_bytes(),
                nocase: modifiers.to_ascii_lowercase().contains("nocase"),
            });
        }
    }
    literals
}

#[cfg(feature = "yara")]
fn find_literal_offsets(bytes: &[u8], literal: &YaraLiteral) -> Vec<usize> {
    if literal.value.is_empty() || literal.value.len() > bytes.len() {
        return Vec::new();
    }
    let haystack;
    let needle;
    let (bytes, literal_bytes) = if literal.nocase {
        haystack = bytes.to_ascii_lowercase();
        needle = literal.value.to_ascii_lowercase();
        (haystack.as_slice(), needle.as_slice())
    } else {
        (bytes, literal.value.as_slice())
    };

    bytes
        .windows(literal_bytes.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == literal_bytes).then_some(offset))
        .collect()
}

#[cfg(feature = "yara")]
fn yara_finding(
    candidate: &ScanCandidate,
    file_hash: &str,
    modified_at: &str,
    rule: &LiteYaraRule,
    match_count: usize,
    index: usize,
) -> Finding {
    let severity = Severity::from_score(55);
    Finding {
        finding_id: format!("YARA-{index:06}"),
        timestamp: (modified_at != "unknown").then(|| modified_at.to_string()),
        severity,
        score: 55,
        confidence: crate::model::confidence_for(55, EvidenceQuality::Q1),
        evidence_quality: EvidenceQuality::Q1,
        evidence_quality_basis:
            "Q1 direct file evidence from local YARA rule match and file hash".to_string(),
        score_breakdown: ScoreBreakdown::from_final_score(55),
        category: "yara_match".to_string(),
        rule_id: format!("YARA-{}", rule.name),
        rule_name: rule.name.clone(),
        source_type: "file".to_string(),
        source_file: Some(candidate.path.display().to_string()),
        line_number: None,
        remote_ip: None,
        method: None,
        uri_path: Some(format!(
            "{}:{}",
            file_extension(&candidate.path),
            candidate.path.display()
        )),
        status: None,
        evidence_summary: format!(
            "YARA literal adapter matched rule {} in {} ({} literal offset(s), sha256 {}). Treat as suspicious evidence, not proof of compromise.",
            rule.name,
            candidate.path.display(),
            match_count,
            file_hash
        ),
        raw_hash: Some(file_hash.to_string()),
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: "Review the rule source, file content, and adjacent host/Web context before escalation.".to_string(),
    }
}
