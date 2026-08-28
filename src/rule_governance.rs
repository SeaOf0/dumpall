use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ResolvedRun;
use crate::detectors::rule_engine;
use crate::error::Result;
use crate::output::paths::OutputLayout;
use crate::output::writers;

#[derive(Debug, Serialize)]
struct RulesManifest {
    name: String,
    version: String,
    created_at: String,
    rule_count: usize,
    enabled_rule_count: usize,
    disabled_rule_count: usize,
    categories: Vec<String>,
    sources: Vec<String>,
    checksum: String,
    files: Vec<RuleFileSummary>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RuleFileSummary {
    path: String,
    sha256: String,
    schema_version: Option<u32>,
    rule_count: usize,
    enabled_rule_count: usize,
    categories: Vec<String>,
    sources: Vec<String>,
}

pub fn write_rule_governance_outputs(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<()> {
    let loaded = rule_engine::load_rule_sets(&resolved.rules)?;
    // allowlist 中无法解析的 IP/CIDR 条目写入治理 notes（检测阶段同样会记日志）。
    let mut allowlist_notes = Vec::new();
    if let Ok(allowlist) = crate::detectors::allowlist::Allowlist::load(resolved.allowlist.as_deref())
    {
        for warning in &allowlist.warnings {
            allowlist_notes.push(format!("allowlist: {warning}"));
        }
    }
    let mut categories = BTreeMap::<String, usize>::new();
    let mut sources = BTreeMap::<String, usize>::new();
    let mut enabled_rule_count = 0;
    let mut disabled_rule_count = 0;
    let mut file_summaries = Vec::new();
    let mut checksum_input = String::new();

    for file in loaded {
        checksum_input.push_str(&file.sha256);
        checksum_input.push('\n');
        let mut file_categories = BTreeMap::<String, usize>::new();
        let mut file_sources = BTreeMap::<String, usize>::new();
        let mut file_enabled_count = 0;

        for rule in &file.rule_set.rules {
            *categories.entry(rule.category.clone()).or_default() += 1;
            *sources.entry(rule.source.clone()).or_default() += 1;
            *file_categories.entry(rule.category.clone()).or_default() += 1;
            *file_sources.entry(rule.source.clone()).or_default() += 1;
            if rule.enabled {
                enabled_rule_count += 1;
                file_enabled_count += 1;
            } else {
                disabled_rule_count += 1;
            }
        }

        file_summaries.push(RuleFileSummary {
            path: if file.embedded {
                file.path.to_string_lossy().to_string()
            } else {
                file.path.display().to_string()
            },
            sha256: format!("sha256:{}", file.sha256),
            schema_version: file.rule_set.schema_version,
            rule_count: file.rule_set.rules.len(),
            enabled_rule_count: file_enabled_count,
            categories: file_categories.into_keys().collect(),
            sources: file_sources.into_keys().collect(),
        });
    }

    let manifest = RulesManifest {
        name: "dumpall-effective-rules".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: crate::time_utils::now_iso(),
        rule_count: enabled_rule_count + disabled_rule_count,
        enabled_rule_count,
        disabled_rule_count,
        categories: categories.into_keys().collect(),
        sources: sources.into_keys().collect(),
        checksum: format!("sha256:{}", sha256_hex(checksum_input.as_bytes())),
        files: file_summaries,
        notes: {
            let mut notes = vec![
                "Rules are local and offline; findings remain suspicious evidence for manual review."
                    .to_string(),
                "Rule version defaults to 1 when an older rule omits an explicit version field."
                    .to_string(),
            ];
            notes.extend(allowlist_notes);
            notes
        },
    };

    writers::write_json_pretty(&layout.rules_manifest, &manifest)?;
    write_effective_allowlist(resolved.allowlist.as_deref(), &layout.effective_allowlist)
}

fn write_effective_allowlist(source: Option<&Path>, destination: &Path) -> Result<()> {
    match source {
        Some(path) => {
            let content = fs::read_to_string(path)?;
            writers::write_text(destination, &content)
        }
        None => writers::write_text(
            destination,
            "# No allowlist file was supplied for this run.\n",
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
