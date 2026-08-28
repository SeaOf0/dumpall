use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{Finding, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineReport {
    pub enabled: bool,
    pub baseline_dir: Option<String>,
    pub baseline_findings: usize,
    pub baseline_files: usize,
    pub baseline_urls: usize,
    pub repeated_findings: usize,
    pub repeated_files: usize,
    pub new_remote_ips: usize,
    pub new_urls: usize,
    pub new_files: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct BaselineIndex {
    findings: BTreeSet<String>,
    files: BTreeSet<String>,
    urls: BTreeSet<String>,
    remote_ips: BTreeSet<String>,
    services: BTreeSet<String>,
    startup_items: BTreeSet<String>,
    network_targets: BTreeSet<String>,
}

pub fn apply_baseline(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    findings: &mut [Finding],
) -> Result<BaselineReport> {
    let Some(path) = resolved.baseline.as_deref() else {
        return Ok(BaselineReport::default());
    };

    let index = BaselineIndex::load(path)?;
    let mut report = BaselineReport {
        enabled: true,
        baseline_dir: Some(path.display().to_string()),
        baseline_findings: index.findings.len(),
        baseline_files: index.files.len(),
        baseline_urls: index.urls.len(),
        notes: vec![
            "Baseline comparison is local and conservative; repeated evidence is down-weighted but not deleted."
                .to_string(),
        ],
        ..BaselineReport::default()
    };

    let mut seen_remote_ips = BTreeSet::new();
    let mut seen_urls = BTreeSet::new();
    let mut seen_files = BTreeSet::new();

    for finding in findings {
        if let Some(remote_ip) = finding
            .remote_ip
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            if !index.remote_ips.contains(remote_ip)
                && seen_remote_ips.insert(remote_ip.to_string())
            {
                report.new_remote_ips += 1;
            }
        }
        if let Some(uri_path) = finding
            .uri_path
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            if !index.urls.contains(uri_path) && seen_urls.insert(uri_path.to_string()) {
                report.new_urls += 1;
            }
        }
        if is_file_finding(finding) {
            if let Some(file_key) = file_key_from_finding(finding) {
                if !index.files.contains(&file_key) && seen_files.insert(file_key) {
                    report.new_files += 1;
                }
            }
        }

        let signature = finding_signature(finding);
        if index.findings.contains(&signature) {
            report.repeated_findings += 1;
            downrank_repeated_finding(finding);
        }

        if is_file_finding(finding)
            && file_key_from_finding(finding)
                .map(|file_key| index.files.contains(&file_key))
                .unwrap_or(false)
        {
            report.repeated_files += 1;
            downrank_repeated_file(finding);
        }
    }

    let current_services = read_first_column(&layout.services)?;
    let current_startup_items = read_first_column(&layout.startup_items)?;
    let current_network_targets = read_network_targets(&layout.network_connections)?;
    let new_services = count_new(&current_services, &index.services);
    let new_startup_items = count_new(&current_startup_items, &index.startup_items);
    let new_network_targets = count_new(&current_network_targets, &index.network_targets);

    if new_services > 0 {
        report.notes.push(format!(
            "baseline: {new_services} new service row(s) observed."
        ));
    }
    if new_startup_items > 0 {
        report.notes.push(format!(
            "baseline: {new_startup_items} new startup item row(s) observed."
        ));
    }
    if new_network_targets > 0 {
        report.notes.push(format!(
            "baseline: {new_network_targets} new network target(s) observed."
        ));
    }

    writers::write_json_pretty(
        &layout.rules_used_dir.join("baseline_summary.json"),
        &report,
    )?;
    Ok(report)
}

impl BaselineIndex {
    fn load(root: &Path) -> Result<Self> {
        let mut index = Self::default();
        index.load_findings(&root.join("findings").join("findings.jsonl"))?;
        index.load_files(&root.join("findings").join("suspicious_files.csv"))?;
        index.load_files(&root.join("evidence").join("file_hashes.csv"))?;
        index.services = read_first_column(&root.join("collection").join("services.csv"))?;
        index.startup_items =
            read_first_column(&root.join("collection").join("startup_items.csv"))?;
        index.network_targets =
            read_network_targets(&root.join("collection").join("network_connections.csv"))?;
        Ok(index)
    }

    fn load_findings(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let content = fs::read_to_string(path)?;
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(finding) = serde_json::from_str::<Finding>(line) else {
                continue;
            };
            self.findings.insert(finding_signature(&finding));
            if let Some(uri_path) = finding.uri_path.as_ref().filter(|value| !value.is_empty()) {
                self.urls.insert(uri_path.clone());
            }
            if let Some(remote_ip) = finding.remote_ip.as_ref().filter(|value| !value.is_empty()) {
                self.remote_ips.insert(remote_ip.clone());
            }
            if is_file_finding(&finding) {
                if let Some(file_key) = file_key_from_finding(&finding) {
                    self.files.insert(file_key);
                }
            }
        }
        Ok(())
    }

    fn load_files(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
        let headers = reader.headers()?.clone();
        for row in reader.records().flatten() {
            if let Some(hash) = get_csv(&headers, &row, &["file_sha256", "sha256"]) {
                self.files.insert(format!("sha256:{hash}"));
                continue;
            }
            if let Some(path) = get_csv(&headers, &row, &["path", "file_path"]) {
                self.files
                    .insert(format!("path:{}", normalize_path_for_baseline(&path)));
            }
        }
        Ok(())
    }
}

fn downrank_repeated_finding(finding: &mut Finding) {
    finding.score = finding.score.saturating_sub(10);
    finding.severity = Severity::from_score(finding.score);
    finding.evidence_summary.push_str(
        " Baseline context: similar finding existed in the supplied baseline; score was reduced but evidence retained.",
    );
    append_basis(finding, "baseline repeated finding");
}

fn downrank_repeated_file(finding: &mut Finding) {
    finding.score = finding.score.saturating_sub(10);
    finding.severity = Severity::from_score(finding.score);
    finding.evidence_summary.push_str(
        " Baseline context: file hash or path existed in the supplied baseline; review only if other evidence changed.",
    );
    append_basis(finding, "baseline repeated file");
}

fn append_basis(finding: &mut Finding, note: &str) {
    let basis = finding.evidence_chain_basis.get_or_insert_with(String::new);
    if !basis.is_empty() {
        basis.push_str("; ");
    }
    basis.push_str(note);
}

fn finding_signature(finding: &Finding) -> String {
    // 日志类(access/db/waf/app)finding 的 raw_hash 逐行不同,把 hash 排进签名
    // 会让基线重复检测形同虚设;改用 rule_id+source_file 粗粒度签名,
    // 同一规则在同一日志文件里再次出现即视为重复。
    if is_log_stream_finding(finding) {
        return [
            finding.rule_id.as_str(),
            finding.source_type.as_str(),
            finding.source_file.as_deref().unwrap_or_default(),
        ]
        .join("|");
    }
    [
        finding.rule_id.as_str(),
        finding.source_type.as_str(),
        finding.remote_ip.as_deref().unwrap_or_default(),
        finding.uri_path.as_deref().unwrap_or_default(),
        finding.source_file.as_deref().unwrap_or_default(),
        finding.raw_hash.as_deref().unwrap_or_default(),
    ]
    .join("|")
}

fn is_log_stream_finding(finding: &Finding) -> bool {
    matches!(
        finding.source_type.as_str(),
        "access_log" | "db_log" | "waf_log" | "app_log"
    )
}

fn is_file_finding(finding: &Finding) -> bool {
    finding.source_type == "file"
        || matches!(finding.category.as_str(), "webshell_static" | "yara_match")
}

fn file_key_from_finding(finding: &Finding) -> Option<String> {
    finding
        .raw_hash
        .as_ref()
        .filter(|value| !value.is_empty())
        .map(|value| format!("sha256:{value}"))
        .or_else(|| {
            finding
                .source_file
                .as_ref()
                .filter(|value| !value.is_empty())
                .map(|value| format!("path:{}", normalize_path_for_baseline(value)))
        })
}

fn normalize_path_for_baseline(path: &str) -> String {
    // 用全路径(统一分隔符 + 小写)作键:只取 basename 会把不同目录下的同名
    // 文件(如各自 web 根下的 index.php)互相抵消。原路径没有目录部分时,
    // 全路径即 basename,无需单独回退。
    path.replace('\\', "/").to_ascii_lowercase()
}

fn read_first_column(path: &Path) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    if !path.exists() {
        return Ok(values);
    }
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    for row in reader.records().flatten() {
        if let Some(value) = row.get(0).map(str::trim).filter(|value| !value.is_empty()) {
            values.insert(value.to_ascii_lowercase());
        }
    }
    Ok(values)
}

fn read_network_targets(path: &Path) -> Result<BTreeSet<String>> {
    let mut values = BTreeSet::new();
    if !path.exists() {
        return Ok(values);
    }
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    let headers = reader.headers()?.clone();
    for row in reader.records().flatten() {
        let remote_address = get_csv(&headers, &row, &["remote_address"]).unwrap_or_default();
        let remote_port = get_csv(&headers, &row, &["remote_port"]).unwrap_or_default();
        if !remote_address.is_empty() {
            values.insert(format!("{remote_address}:{remote_port}").to_ascii_lowercase());
        }
    }
    Ok(values)
}

fn count_new(current: &BTreeSet<String>, baseline: &BTreeSet<String>) -> usize {
    current
        .iter()
        .filter(|value| !baseline.contains(*value))
        .count()
}

fn get_csv(headers: &csv::StringRecord, row: &csv::StringRecord, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
            .and_then(|index| row.get(index))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}
