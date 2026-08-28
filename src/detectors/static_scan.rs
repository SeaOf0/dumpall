use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::collectors::collection_error;
use crate::collectors::filesystem::{has_double_extension, is_high_risk_extension};
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::file_inspect::{entropy, magic, script_rules};
use crate::model::{CollectionError, Finding, ScoreBreakdown, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

const MAX_STATIC_FILES_PER_RUN: u64 = 50_000;
const SUSPICIOUS_STATIC_HEADER: &str = "path,root_path,size_bytes,modified_at,extension,file_sha256,magic_type,magic_mismatch,entropy,max_line_entropy,long_base64_run,high_risk_extension,double_extension,recent_change,dynamic_execution,command_execution,reflection,http_param_bridge,suspicious_filename,score,severity,reason,recommendation\n";
const FILE_HASH_HEADER: &str =
    "path,root_path,size_bytes,modified_at,sha256,magic_type,extension,scanned_by\n";

#[derive(Debug, Default)]
pub struct StaticScanReport {
    pub files_scanned: u64,
    pub suspicious_files: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<CollectionError>,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanCandidate {
    pub root: PathBuf,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Serialize)]
struct SuspiciousStaticRow {
    path: String,
    root_path: String,
    size_bytes: u64,
    modified_at: String,
    extension: String,
    file_sha256: String,
    magic_type: String,
    magic_mismatch: bool,
    entropy: String,
    max_line_entropy: String,
    long_base64_run: usize,
    high_risk_extension: bool,
    double_extension: bool,
    recent_change: bool,
    dynamic_execution: bool,
    command_execution: bool,
    reflection: bool,
    http_param_bridge: bool,
    suspicious_filename: bool,
    score: u16,
    severity: String,
    reason: String,
    recommendation: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct FileHashRow {
    path: String,
    root_path: String,
    size_bytes: u64,
    modified_at: String,
    sha256: String,
    magic_type: String,
    extension: String,
    scanned_by: String,
}

struct StaticAssessment {
    row: SuspiciousStaticRow,
    finding: Option<Finding>,
}

struct FileInspection<'a> {
    bytes: &'a [u8],
    file_hash: String,
    magic_type: magic::MagicType,
    modified_at: String,
    extension: String,
}

pub fn run_static_scan(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<StaticScanReport> {
    let mut errors = Vec::new();
    let candidates = collect_scan_candidates(
        resolved,
        layout,
        resolved.max_static_file_size_mb,
        "static_scan",
        &mut errors,
    )?;
    logger.log(format!(
        "static_scan: {} candidate file(s) within configured roots",
        candidates.len()
    ))?;

    let mut suspicious_rows = Vec::new();
    let mut hash_rows = Vec::new();
    let mut findings = Vec::new();

    for candidate in &candidates {
        let bytes = match fs::read(&candidate.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(collection_error(
                    "static_scan",
                    candidate.path.display().to_string(),
                    "read_file",
                    "file could not be read for static inspection",
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        let file_hash = hash_bytes(&bytes);
        let magic_type = magic::detect(&bytes);
        let modified_at = file_modified_iso(candidate.modified);
        let extension = file_extension(&candidate.path);
        let inspection = FileInspection {
            bytes: &bytes,
            file_hash,
            magic_type,
            modified_at,
            extension,
        };

        hash_rows.push(FileHashRow {
            path: candidate.path.display().to_string(),
            root_path: candidate.root.display().to_string(),
            size_bytes: candidate.size_bytes,
            modified_at: inspection.modified_at.clone(),
            sha256: inspection.file_hash.clone(),
            magic_type: inspection.magic_type.as_str().to_string(),
            extension: inspection.extension.clone(),
            scanned_by: "static_scan".to_string(),
        });

        if let Some(assessment) =
            assess_candidate(resolved, candidate, &inspection, findings.len() + 1)
        {
            if let Some(finding) = assessment.finding {
                findings.push(finding);
            }
            suspicious_rows.push(assessment.row);
        }
    }

    write_suspicious_rows(&layout.suspicious_files, &suspicious_rows)?;
    write_hash_rows(&layout.file_hashes, &hash_rows)?;

    Ok(StaticScanReport {
        files_scanned: candidates.len() as u64,
        suspicious_files: suspicious_rows.len(),
        findings,
        errors,
    })
}

fn assess_candidate(
    resolved: &ResolvedRun,
    candidate: &ScanCandidate,
    inspection: &FileInspection<'_>,
    finding_index: usize,
) -> Option<StaticAssessment> {
    let bytes = inspection.bytes;
    let file_hash = inspection.file_hash.as_str();
    let modified_at = inspection.modified_at.as_str();
    let extension = inspection.extension.as_str();
    let magic_type = inspection.magic_type;
    let high_risk_extension = is_high_risk_extension(extension);
    let double_extension = has_double_extension(&candidate.path);
    let magic_mismatch = magic::extension_mismatch(extension, magic_type);
    let overall_entropy = entropy::shannon_entropy(bytes);
    let max_line_entropy = entropy::max_line_entropy(bytes);
    let long_base64_run = entropy::longest_base64_run(bytes);
    let text = std::str::from_utf8(bytes).unwrap_or_default();
    let signals = script_rules::analyze(&candidate.path, text);
    let recent_change = is_recent(candidate.modified, since_system_time(resolved));
    let high_entropy = overall_entropy >= 7.2 || max_line_entropy >= 5.7;
    let long_base64 = long_base64_run >= 120;
    let small_file_high_risk = candidate.size_bytes <= 4096
        && (signals.dynamic_execution || signals.command_execution || signals.http_param_bridge);

    let mut score = 0_u16;
    let mut reasons = Vec::new();
    add_reason(
        &mut score,
        &mut reasons,
        high_risk_extension,
        20,
        "high_risk_extension",
    );
    add_reason(
        &mut score,
        &mut reasons,
        double_extension,
        20,
        "double_extension",
    );
    add_reason(
        &mut score,
        &mut reasons,
        magic_mismatch,
        25,
        "magic_mismatch",
    );
    add_reason(&mut score, &mut reasons, recent_change, 10, "recent_change");
    add_reason(&mut score, &mut reasons, high_entropy, 10, "high_entropy");
    add_reason(&mut score, &mut reasons, long_base64, 15, "long_base64");
    add_reason(
        &mut score,
        &mut reasons,
        signals.dynamic_execution,
        25,
        "dynamic_execution",
    );
    add_reason(
        &mut score,
        &mut reasons,
        signals.command_execution,
        25,
        "command_execution",
    );
    add_reason(
        &mut score,
        &mut reasons,
        signals.reflection,
        15,
        "reflection",
    );
    add_reason(
        &mut score,
        &mut reasons,
        signals.http_param_bridge,
        20,
        "http_param_bridge",
    );
    add_reason(
        &mut score,
        &mut reasons,
        signals.suspicious_filename,
        10,
        "suspicious_filename",
    );
    add_reason(
        &mut score,
        &mut reasons,
        small_file_high_risk,
        10,
        "small_file_high_risk",
    );
    score = score.min(100);

    let has_static_indicator = high_risk_extension
        || double_extension
        || magic_mismatch
        || high_entropy
        || long_base64
        || signals.dynamic_execution
        || signals.command_execution
        || signals.reflection
        || signals.http_param_bridge
        || signals.suspicious_filename
        || small_file_high_risk;
    let should_record = has_static_indicator || score >= 50;
    if !should_record {
        return None;
    }

    let severity = Severity::from_score(score);
    let recommendation =
        "Review the file content, deployment history, upload logs, and adjacent process/network evidence before concluding malicious activity.";
    let reason = if reasons.is_empty() {
        "static_inventory".to_string()
    } else {
        reasons.join(";")
    };
    let row = SuspiciousStaticRow {
        path: candidate.path.display().to_string(),
        root_path: candidate.root.display().to_string(),
        size_bytes: candidate.size_bytes,
        modified_at: modified_at.to_string(),
        extension: extension.to_string(),
        file_sha256: file_hash.to_string(),
        magic_type: magic_type.as_str().to_string(),
        magic_mismatch,
        entropy: format!("{overall_entropy:.2}"),
        max_line_entropy: format!("{max_line_entropy:.2}"),
        long_base64_run,
        high_risk_extension,
        double_extension,
        recent_change,
        dynamic_execution: signals.dynamic_execution,
        command_execution: signals.command_execution,
        reflection: signals.reflection,
        http_param_bridge: signals.http_param_bridge,
        suspicious_filename: signals.suspicious_filename,
        score,
        severity: severity.as_str().to_string(),
        reason: reason.clone(),
        recommendation: recommendation.to_string(),
    };

    let finding = (score >= 50).then(|| Finding {
        finding_id: format!("FILE-{finding_index:06}"),
        timestamp: (modified_at != "unknown").then(|| modified_at.to_string()),
        severity,
        score,
        confidence: crate::model::confidence_for(score, crate::model::EvidenceQuality::Q1),
        evidence_quality: crate::model::EvidenceQuality::Q1,
        evidence_quality_basis: "Q1 direct file evidence from static metadata, content signals, and file hash".to_string(),
        score_breakdown: ScoreBreakdown::from_final_score(score),
        category: "webshell_static".to_string(),
        rule_id: "FILE-WEBSHELL-STATIC-001".to_string(),
        rule_name: "Built-in WebShell static file indicators".to_string(),
        source_type: "file".to_string(),
        source_file: Some(candidate.path.display().to_string()),
        line_number: None,
        remote_ip: None,
        method: None,
        uri_path: None,
        status: None,
        evidence_summary: format!(
            "Static file inspection found {reason} in {} with sha256 {}. Treat as suspicious evidence, not proof of compromise.",
            candidate.path.display(),
            file_hash
        ),
        raw_hash: Some(file_hash.to_string()),
        related_ids: Vec::new(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
        recommendation: recommendation.to_string(),
    });

    Some(StaticAssessment { row, finding })
}

fn add_reason(
    score: &mut u16,
    reasons: &mut Vec<&'static str>,
    condition: bool,
    value: u16,
    reason: &'static str,
) {
    if condition {
        *score = score.saturating_add(value);
        reasons.push(reason);
    }
}

fn write_suspicious_rows(path: &Path, rows: &[SuspiciousStaticRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, SUSPICIOUS_STATIC_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

fn write_hash_rows(path: &Path, rows: &[FileHashRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, FILE_HASH_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

pub(crate) fn collect_scan_candidates(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    max_file_size_mb: u64,
    operation: &'static str,
    errors: &mut Vec<CollectionError>,
) -> Result<Vec<ScanCandidate>> {
    let roots = roots_for_scan(resolved, layout)?;
    let mut candidates = Vec::new();
    let max_bytes = max_file_size_mb.saturating_mul(1024 * 1024);
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        scan_root(
            &root,
            &root,
            0,
            resolved.safety.max_depth,
            max_bytes,
            operation,
            errors,
            &mut candidates,
        );
        if candidates.len() as u64 >= MAX_STATIC_FILES_PER_RUN {
            break;
        }
    }
    Ok(candidates)
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub(crate) fn file_modified_iso(modified: Option<SystemTime>) -> String {
    modified
        .map(system_time_to_iso)
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn file_extension(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn roots_for_scan(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<Vec<PathBuf>> {
    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();

    for path in &resolved.web_paths {
        push_root(path, &mut seen, &mut roots);
    }

    if layout.web_roots.exists() {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(&layout.web_roots)?;
        let headers = reader.headers()?.clone();
        let path_index = headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case("path"));
        let exists_index = headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case("exists"));
        for row in reader.records().flatten() {
            let Some(path_index) = path_index else {
                continue;
            };
            if let Some(exists_index) = exists_index {
                let exists = row.get(exists_index).unwrap_or_default();
                if exists.eq_ignore_ascii_case("false") {
                    continue;
                }
            }
            if let Some(path) = row.get(path_index) {
                push_root(Path::new(path), &mut seen, &mut roots);
            }
        }
    }

    Ok(roots)
}

fn push_root(path: &Path, seen: &mut BTreeSet<String>, roots: &mut Vec<PathBuf>) {
    let key = path.display().to_string().to_ascii_lowercase();
    if seen.insert(key) {
        roots.push(path.to_path_buf());
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_root(
    root: &Path,
    current: &Path,
    depth: usize,
    max_depth: usize,
    max_bytes: u64,
    operation: &'static str,
    errors: &mut Vec<CollectionError>,
    candidates: &mut Vec<ScanCandidate>,
) {
    if candidates.len() as u64 >= MAX_STATIC_FILES_PER_RUN {
        errors.push(collection_error(
            operation,
            root.display().to_string(),
            "scan_root",
            "static scan file limit reached",
            Some(format!("limit={MAX_STATIC_FILES_PER_RUN}")),
        ));
        return;
    }
    if depth > max_depth {
        return;
    }

    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(collection_error(
                operation,
                current.display().to_string(),
                "read_dir",
                "directory could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };
    // 按 file_name 排序保证遍历顺序可复现（截断前顺序稳定，避免 OS 目录顺序
    // 差异导致 50k 上限截断的文件集合不可比）。
    let mut sorted_entries = entries
        .flatten()
        .map(|entry| (entry.file_name(), entry))
        .collect::<Vec<_>>();
    sorted_entries.sort_by(|left, right| left.0.cmp(&right.0));

    for (_, entry) in sorted_entries {
        if candidates.len() as u64 >= MAX_STATIC_FILES_PER_RUN {
            break;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                errors.push(collection_error(
                    operation,
                    path.display().to_string(),
                    "file_type",
                    "file type could not be read",
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            scan_root(
                root,
                &path,
                depth + 1,
                max_depth,
                max_bytes,
                operation,
                errors,
                candidates,
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(collection_error(
                    operation,
                    path.display().to_string(),
                    "metadata",
                    "metadata could not be read",
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        if metadata.len() > max_bytes {
            errors.push(collection_error(
                operation,
                path.display().to_string(),
                "size_limit",
                "file skipped because it exceeds configured static scan limit",
                Some(format!(
                    "size_bytes={}, max_bytes={}",
                    metadata.len(),
                    max_bytes
                )),
            ));
            continue;
        }
        candidates.push(ScanCandidate {
            root: root.to_path_buf(),
            path,
            size_bytes: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
}

fn since_system_time(resolved: &ResolvedRun) -> Option<SystemTime> {
    resolved
        .time_range
        .since
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
        .map(|value| {
            let timestamp = value.unix_timestamp();
            if timestamp >= 0 {
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)
            } else {
                SystemTime::UNIX_EPOCH
            }
        })
}

fn is_recent(modified: Option<SystemTime>, since: Option<SystemTime>) -> bool {
    match (modified, since) {
        (Some(modified), Some(since)) => modified >= since,
        _ => false,
    }
}

fn system_time_to_iso(value: SystemTime) -> String {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
            else {
                return "unknown".to_string();
            };
            crate::time_utils::format_iso(datetime)
        }
        Err(_) => "unknown".to_string(),
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
