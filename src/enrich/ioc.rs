use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::collectors::collection_error;
use crate::error::Result;
use crate::model::{
    CollectionError, DbLogEvent, EvidenceQuality, Finding, HttpLogEvent, ScoreBreakdown, Severity,
};
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::identity::{canonical_ip, parse_ip_token, Cidr};

const IOC_MATCH_HEADER: &str = "match_id,timestamp,indicator_type,indicator_value,matched_field,matched_value,source,confidence,tags,description,evidence_source,evidence_line,score_delta,recommendation\n";

#[derive(Debug, Default)]
pub struct IocReport {
    pub matches: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<CollectionError>,
    pub sources: Vec<IocSourceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSourceSummary {
    pub path: String,
    pub records_loaded: usize,
    pub status: String,
}

#[derive(Debug, Clone)]
struct IocEntry {
    indicator_type: IocType,
    value: String,
    source: String,
    confidence: String,
    tags: String,
    description: String,
    cidr: Option<Cidr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IocType {
    Ip,
    Cidr,
    Domain,
    UrlPath,
    Hash,
    UserAgent,
}

impl IocType {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ip" => Some(Self::Ip),
            "cidr" => Some(Self::Cidr),
            "domain" | "host" => Some(Self::Domain),
            "url" | "url_path" | "path" => Some(Self::UrlPath),
            "hash" | "sha256" | "sha1" | "md5" => Some(Self::Hash),
            "user_agent" | "ua" => Some(Self::UserAgent),
            _ => None,
        }
    }

    fn infer(value: &str) -> Self {
        let trimmed = value.trim();
        if trimmed.contains('/') && Cidr::parse(trimmed).is_ok() {
            Self::Cidr
        } else if parse_ip_token(trimmed).is_some() {
            Self::Ip
        } else if is_hash_like(trimmed) {
            Self::Hash
        } else if trimmed.starts_with('/') || has_path_extension(trimmed) {
            Self::UrlPath
        } else if trimmed.contains('.') && !trimmed.contains(' ') {
            Self::Domain
        } else {
            Self::UserAgent
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
            Self::UrlPath => "url_path",
            Self::Hash => "hash",
            Self::UserAgent => "user_agent",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct IocMatchRow {
    match_id: String,
    timestamp: String,
    indicator_type: String,
    indicator_value: String,
    matched_field: String,
    matched_value: String,
    source: String,
    confidence: String,
    tags: String,
    description: String,
    evidence_source: String,
    evidence_line: String,
    score_delta: u16,
    recommendation: String,
}

pub fn run_ioc_matching(paths: &[std::path::PathBuf], layout: &OutputLayout) -> Result<IocReport> {
    let mut report = IocReport::default();
    let mut entries = Vec::new();

    for path in paths {
        match load_ioc_file(path) {
            Ok(mut loaded) => {
                if loaded.skipped_rows > 0 {
                    // 单条坏行只计数告警,库继续加载,不再让整库失效。
                    report.errors.push(collection_error(
                        "ioc",
                        path.display().to_string(),
                        "parse",
                        format!(
                            "{} malformed or unrecognizable IOC row(s) were skipped while loading",
                            loaded.skipped_rows
                        ),
                        None,
                    ));
                }
                let short_hash_indicators = short_hash_indicator_count(&loaded.entries);
                if short_hash_indicators > 0 {
                    // 证据侧只有 sha256 字段,md5/sha1 指示器无法比对:跳过并告警。
                    report.errors.push(collection_error(
                        "ioc",
                        path.display().to_string(),
                        "parse",
                        format!(
                            "{short_hash_indicators} md5/sha1 IOC indicator(s) cannot be compared: collected evidence only carries sha256 file hashes; they were skipped"
                        ),
                        None,
                    ));
                }
                report.sources.push(IocSourceSummary {
                    path: path.display().to_string(),
                    records_loaded: loaded.entries.len(),
                    status: "loaded".to_string(),
                });
                entries.append(&mut loaded.entries);
            }
            Err(error) => {
                report.sources.push(IocSourceSummary {
                    path: path.display().to_string(),
                    records_loaded: 0,
                    status: "error".to_string(),
                });
                report.errors.push(collection_error(
                    "ioc",
                    path.display().to_string(),
                    "load",
                    "IOC file could not be loaded",
                    Some(error),
                ));
            }
        }
    }

    let mut rows = Vec::new();
    let mut findings = Vec::new();

    let (http_events, skipped_http) = read_jsonl::<HttpLogEvent>(&layout.http_events)?;
    if skipped_http > 0 {
        report.errors.push(skipped_jsonl_warning(
            &layout.http_events,
            skipped_http,
        ));
    }
    for event in http_events {
        for (field, value) in http_candidate_fields(&event) {
            add_matches_for_value(
                &entries,
                &mut rows,
                &mut findings,
                MatchContext {
                    field,
                    value,
                    timestamp: event.timestamp.as_deref().unwrap_or_default(),
                    evidence_source: &event.source_file,
                    evidence_line: Some(event.line_number),
                    remote_ip: event.effective_remote_ip(),
                    uri_path: event.uri_path.as_deref(),
                },
            );
        }
    }

    let (db_events, skipped_db) = read_jsonl::<DbLogEvent>(&layout.db_events)?;
    if skipped_db > 0 {
        report.errors.push(skipped_jsonl_warning(
            &layout.db_events,
            skipped_db,
        ));
    }
    for event in db_events {
        if let Some(client_ip) = event.client_ip.as_deref() {
            add_matches_for_value(
                &entries,
                &mut rows,
                &mut findings,
                MatchContext {
                    field: "db_client_ip",
                    value: client_ip,
                    timestamp: event.timestamp.as_deref().unwrap_or_default(),
                    evidence_source: &event.source_file,
                    evidence_line: Some(event.line_number),
                    remote_ip: event.client_ip.as_deref(),
                    uri_path: None,
                },
            );
        }
    }

    for row in read_file_hash_rows(&layout.file_hashes)? {
        add_matches_for_value(
            &entries,
            &mut rows,
            &mut findings,
            MatchContext {
                field: "file_sha256",
                value: &row.sha256,
                timestamp: row.modified_at.as_str(),
                evidence_source: &row.path,
                evidence_line: None,
                remote_ip: None,
                uri_path: None,
            },
        );
    }

    write_matches(&layout.ioc_matches, &rows)?;
    writers::write_json_pretty(&layout.ioc_sources, &report.sources)?;

    report.matches = rows.len();
    report.findings = findings;
    Ok(report)
}

struct MatchContext<'a> {
    field: &'a str,
    value: &'a str,
    timestamp: &'a str,
    evidence_source: &'a str,
    evidence_line: Option<u64>,
    remote_ip: Option<&'a str>,
    uri_path: Option<&'a str>,
}

fn add_matches_for_value(
    entries: &[IocEntry],
    rows: &mut Vec<IocMatchRow>,
    findings: &mut Vec<Finding>,
    context: MatchContext<'_>,
) {
    for entry in entries {
        if !entry.matches(context.field, context.value) {
            continue;
        }
        let match_id = format!("IOC-{number:06}", number = rows.len() + 1);
        let score_delta = score_delta(entry.confidence.as_str());
        let recommendation =
            "Review the local IOC source, confidence, and adjacent evidence before increasing incident severity.";
        rows.push(IocMatchRow {
            match_id: match_id.clone(),
            timestamp: context.timestamp.to_string(),
            indicator_type: entry.indicator_type.as_str().to_string(),
            indicator_value: entry.value.clone(),
            matched_field: context.field.to_string(),
            matched_value: context.value.to_string(),
            source: entry.source.clone(),
            confidence: entry.confidence.clone(),
            tags: entry.tags.clone(),
            description: entry.description.clone(),
            evidence_source: context.evidence_source.to_string(),
            evidence_line: context
                .evidence_line
                .map(|line| line.to_string())
                .unwrap_or_default(),
            score_delta,
            recommendation: recommendation.to_string(),
        });

        let score = (20 + score_delta).min(40);
        findings.push(Finding {
            finding_id: match_id,
            timestamp: (!context.timestamp.is_empty()).then(|| context.timestamp.to_string()),
            severity: Severity::from_score(score),
            score,
            confidence: crate::model::confidence_for(score, EvidenceQuality::Q4),
            evidence_quality: EvidenceQuality::Q4,
            evidence_quality_basis: "Q4 environment context from a local IOC file; auxiliary evidence only".to_string(),
            score_breakdown: {
                let mut breakdown = ScoreBreakdown::from_base(20);
                breakdown.add_enrichment(score_delta);
                breakdown
            },
            category: "ioc_match".to_string(),
            rule_id: "IOC-MATCH-LOCAL".to_string(),
            rule_name: "Local offline IOC match".to_string(),
            source_type: "ioc".to_string(),
            source_file: Some(context.evidence_source.to_string()),
            line_number: context.evidence_line,
            remote_ip: context.remote_ip.map(str::to_string),
            method: None,
            uri_path: context.uri_path.map(str::to_string),
            status: None,
            evidence_summary: format!(
                "Local IOC {} matched {field}. IOC matches are auxiliary suspicious evidence and are not proof of compromise.",
                entry.value,
                field = context.field
            ),
            raw_hash: Some(hash_text(&format!(
                "{}|{}|{}|{}",
                entry.indicator_type.as_str(),
                entry.value,
                context.field,
                context.value
            ))),
            related_ids: Vec::new(),
            evidence_chain_level: None,
            evidence_chain_basis: None,
            recommendation: recommendation.to_string(),
        });
    }
}

fn http_candidate_fields(event: &HttpLogEvent) -> Vec<(&'static str, &str)> {
    let mut fields = Vec::new();
    if let Some(value) = event.effective_remote_ip() {
        fields.push(("remote_ip", value));
    }
    if let Some(value) = event.host.as_deref() {
        fields.push(("host", value));
    }
    if let Some(value) = event.uri_path.as_deref() {
        fields.push(("uri_path", value));
    }
    if let Some(value) = event.user_agent.as_deref() {
        fields.push(("user_agent", value));
    }
    fields
}

impl IocEntry {
    fn matches(&self, field: &str, value: &str) -> bool {
        match self.indicator_type {
            IocType::Ip => {
                // 双侧 canonical 后比较,::ffff:1.2.3.4 与 1.2.3.4 视为同一地址。
                is_ip_field(field)
                    && canonical_ip(value)
                        .zip(canonical_ip(&self.value))
                        .map(|(left, right)| left == right)
                        .unwrap_or(false)
            }
            IocType::Cidr => {
                is_ip_field(field)
                    && canonical_ip(value)
                        .zip(self.cidr.as_ref())
                        .map(|(ip, cidr)| cidr.contains(ip))
                        .unwrap_or(false)
            }
            IocType::Domain => {
                matches!(field, "host") && domain_matches(value, self.value.as_str())
            }
            IocType::UrlPath => {
                matches!(field, "uri_path") && url_path_boundary_match(value, &self.value)
            }
            IocType::Hash => {
                // 证据侧只有 sha256 字段:长度不等的 md5/sha1 指示器直接跳过,
                // 避免与 sha256 摘要做无意义比对。
                matches!(field, "file_sha256")
                    && value.len() == self.value.len()
                    && value.eq_ignore_ascii_case(&self.value)
            }
            IocType::UserAgent => {
                matches!(field, "user_agent")
                    && value
                        .to_ascii_lowercase()
                        .contains(&self.value.to_ascii_lowercase())
            }
        }
    }
}

/// 路径边界匹配:相等,或 path 以 value 起始且断在 '/' 边界上(大小写不敏感)。
/// 禁止裸子串匹配,避免 "/admin" 误报命中 "/administrator"。
fn url_path_boundary_match(path: &str, indicator: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let indicator = indicator.to_ascii_lowercase();
    if path == indicator {
        return true;
    }
    path.starts_with(&indicator)
        && (indicator.ends_with('/') || path[indicator.len()..].starts_with('/'))
}

/// 单个 IOC 文件的加载结果:可用条目 + 被跳过的坏行计数。
#[derive(Debug, Default)]
struct LoadedIocFile {
    entries: Vec<IocEntry>,
    skipped_rows: usize,
}

/// md5(32)/sha1(40) 长度的 hash 指示器数量:证据侧只有 sha256,无法比对。
fn short_hash_indicator_count(entries: &[IocEntry]) -> usize {
    entries
        .iter()
        .filter(|entry| {
            entry.indicator_type == IocType::Hash && matches!(entry.value.len(), 32 | 40)
        })
        .count()
}

fn load_ioc_file(path: &Path) -> std::result::Result<LoadedIocFile, String> {
    if !path.exists() {
        return Err("IOC file does not exist".to_string());
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "csv" => load_csv_iocs(path),
        "json" | "jsonl" => load_json_iocs(path),
        _ => load_text_iocs(path),
    }
}

fn load_csv_iocs(path: &Path) -> std::result::Result<LoadedIocFile, String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|error| error.to_string())?;
    let headers = reader.headers().map_err(|error| error.to_string())?.clone();
    let mut loaded = LoadedIocFile::default();
    for row in reader.records() {
        // 单条坏行(缺 value 列、CIDR 解析失败等)跳过并计数,库继续加载。
        let Ok(row) = row else {
            loaded.skipped_rows += 1;
            continue;
        };
        let Some(value) = get_csv(&headers, &row, &["value", "indicator", "ioc"]) else {
            loaded.skipped_rows += 1;
            continue;
        };
        let type_cell = ["type", "indicator_type"].iter().find_map(|name| {
            headers
                .iter()
                .position(|header| header.eq_ignore_ascii_case(name))
                .and_then(|index| row.get(index))
        });
        let indicator_type = match type_cell {
            // 类型列存在(含空值):必须是可识别类型,否则按坏行跳过并计数,
            // 不静默降级成按值猜测的类型——否则整行变成永不匹配的死条目。
            Some(_) => {
                match get_csv(&headers, &row, &["type", "indicator_type"])
                    .as_deref()
                    .and_then(IocType::parse)
                {
                    Some(parsed) => parsed,
                    None => {
                        loaded.skipped_rows += 1;
                        continue;
                    }
                }
            }
            // 配置里没有类型列:按值推断。
            None => IocType::infer(&value),
        };
        match IocEntry::new(
            indicator_type,
            value,
            get_csv(&headers, &row, &["source"]).unwrap_or_else(|| path.display().to_string()),
            get_csv(&headers, &row, &["confidence"]).unwrap_or_else(|| "medium".to_string()),
            get_csv(&headers, &row, &["tags"]).unwrap_or_default(),
            get_csv(&headers, &row, &["description"]).unwrap_or_default(),
        ) {
            Ok(entry) => loaded.entries.push(entry),
            Err(_) => loaded.skipped_rows += 1,
        }
    }
    Ok(loaded)
}

fn load_json_iocs(path: &Path) -> std::result::Result<LoadedIocFile, String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut loaded = LoadedIocFile::default();
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("jsonl"))
        .unwrap_or(false)
    {
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                loaded.skipped_rows += 1;
                continue;
            };
            match entry_from_json(&value, path) {
                Ok(entry) => loaded.entries.push(entry),
                Err(_) => loaded.skipped_rows += 1,
            }
        }
    } else {
        let value: Value = serde_json::from_str(&content).map_err(|error| error.to_string())?;
        let rows = value
            .as_array()
            .ok_or_else(|| "IOC JSON must be an array of objects".to_string())?;
        for row in rows {
            match entry_from_json(row, path) {
                Ok(entry) => loaded.entries.push(entry),
                Err(_) => loaded.skipped_rows += 1,
            }
        }
    }
    Ok(loaded)
}

fn load_text_iocs(path: &Path) -> std::result::Result<LoadedIocFile, String> {
    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut loaded = LoadedIocFile::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "值,备注" 行:左段不是合法类型名时,用左段(而非整行)推断类型并取值,
        // 右段当备注忽略——按整行取值会生成永不匹配的死条目。
        let (indicator_type, value) = if let Some((left, right)) = line.split_once(',') {
            match IocType::parse(left) {
                Some(indicator_type) => (indicator_type, right.trim().to_string()),
                None => (IocType::infer(left), left.trim().to_string()),
            }
        } else {
            (IocType::infer(line), line.to_string())
        };
        if value.is_empty() {
            loaded.skipped_rows += 1;
            continue;
        }
        match IocEntry::new(
            indicator_type,
            value,
            path.display().to_string(),
            "medium".to_string(),
            String::new(),
            String::new(),
        ) {
            Ok(entry) => loaded.entries.push(entry),
            Err(_) => loaded.skipped_rows += 1,
        }
    }
    Ok(loaded)
}

fn entry_from_json(value: &Value, path: &Path) -> std::result::Result<IocEntry, String> {
    let indicator = json_string(value, &["value", "indicator", "ioc"])
        .ok_or_else(|| "IOC JSON row missing value/indicator/ioc".to_string())?;
    let indicator_type = json_string(value, &["type", "indicator_type"])
        .and_then(|value| IocType::parse(&value))
        .unwrap_or_else(|| IocType::infer(&indicator));
    IocEntry::new(
        indicator_type,
        indicator,
        json_string(value, &["source"]).unwrap_or_else(|| path.display().to_string()),
        json_string(value, &["confidence"]).unwrap_or_else(|| "medium".to_string()),
        json_string(value, &["tags"]).unwrap_or_default(),
        json_string(value, &["description"]).unwrap_or_default(),
    )
}

impl IocEntry {
    fn new(
        indicator_type: IocType,
        value: String,
        source: String,
        confidence: String,
        tags: String,
        description: String,
    ) -> std::result::Result<Self, String> {
        if indicator_type == IocType::Ip && parse_ip_token(&value).is_none() {
            return Err(format!("`{value}` is not a valid IP indicator"));
        }
        let cidr = if indicator_type == IocType::Cidr {
            Some(Cidr::parse(&value)?)
        } else {
            None
        };
        Ok(Self {
            indicator_type,
            value,
            source,
            confidence,
            tags,
            description,
            cidr,
        })
    }
}

#[derive(Debug)]
struct FileHashRow {
    path: String,
    modified_at: String,
    sha256: String,
}

fn read_file_hash_rows(path: &Path) -> Result<Vec<FileHashRow>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    let headers = reader.headers()?.clone();
    let mut rows = Vec::new();
    for row in reader.records().flatten() {
        let path = get_csv(&headers, &row, &["path"]).unwrap_or_default();
        let sha256 = get_csv(&headers, &row, &["sha256"]).unwrap_or_default();
        if sha256.is_empty() {
            continue;
        }
        rows.push(FileHashRow {
            path,
            modified_at: get_csv(&headers, &row, &["modified_at"]).unwrap_or_default(),
            sha256,
        });
    }
    Ok(rows)
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

fn skipped_jsonl_warning(path: &Path, skipped: usize) -> CollectionError {
    collection_error(
        "ioc",
        path.display().to_string(),
        "parse",
        format!("{skipped} malformed JSONL line(s) were skipped while reading evidence events"),
        None,
    )
}

fn write_matches(path: &Path, rows: &[IocMatchRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, IOC_MATCH_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

fn is_ip_field(field: &str) -> bool {
    matches!(field, "remote_ip" | "db_client_ip")
}

fn domain_matches(value: &str, indicator: &str) -> bool {
    let host = value
        .trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let indicator = indicator.trim().trim_end_matches('.').to_ascii_lowercase();
    host == indicator || host.ends_with(&format!(".{indicator}"))
}

fn is_hash_like(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64) && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// xxx.php / xxx.jsp 这类带脚本扩展名的文件名样值按 UrlPath 推断;
/// 当成 Domain 会在路径匹配分支里永远命中不了。
fn has_path_extension(value: &str) -> bool {
    let Some((_, extension)) = value.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "php" | "php5"
            | "php7"
            | "phtml"
            | "jsp"
            | "jspx"
            | "asp"
            | "aspx"
            | "ashx"
            | "asmx"
            | "war"
    )
}

fn score_delta(confidence: &str) -> u16 {
    match confidence.trim().to_ascii_lowercase().as_str() {
        "high" | "strong" => 15,
        "low" | "weak" => 5,
        _ => 10,
    }
}

fn hash_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
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

fn json_string(value: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        value.get(*name).and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_ioc_infers_cidr_and_user_agent() {
        let root = crate::unique_test_dir("ioc");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ioc.txt");
        fs::write(&path, "cidr,203.0.113.0/24\nBadBot\n").unwrap();

        let loaded = load_ioc_file(&path).unwrap();

        assert_eq!(loaded.skipped_rows, 0);
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].indicator_type, IocType::Cidr);
        assert_eq!(loaded.entries[1].indicator_type, IocType::UserAgent);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn text_ioc_remark_line_uses_left_segment_as_value() {
        let root = crate::unique_test_dir("ioc-remark");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ioc.txt");
        fs::write(&path, "evil.php,某次事件备注\n上传目录shell.jsp\n,只有备注\n").unwrap();

        let loaded = load_ioc_file(&path).unwrap();

        // 左段不是类型名时用左段推断并取值,右段忽略;空左段计为坏行。
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.skipped_rows, 1);
        assert_eq!(loaded.entries[0].indicator_type, IocType::UrlPath);
        assert_eq!(loaded.entries[0].value, "evil.php");
        assert_eq!(loaded.entries[1].indicator_type, IocType::UrlPath);
        assert_eq!(loaded.entries[1].value, "上传目录shell.jsp");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn infer_treats_script_filenames_as_url_path() {
        assert_eq!(IocType::infer("shell.php"), IocType::UrlPath);
        assert_eq!(IocType::infer("cmd.jsp"), IocType::UrlPath);
        assert_eq!(IocType::infer("/admin/login"), IocType::UrlPath);
        assert_eq!(IocType::infer("bad.example"), IocType::Domain);
        assert_eq!(IocType::infer("203.0.113.10"), IocType::Ip);
    }

    #[test]
    fn url_path_match_requires_boundary() {
        assert!(url_path_boundary_match("/admin", "/admin"));
        assert!(url_path_boundary_match("/Admin/Upload", "/admin"));
        assert!(url_path_boundary_match("/admin/upload", "/admin/"));
        // 前缀子串不再误报。
        assert!(!url_path_boundary_match("/administrator", "/admin"));
        assert!(!url_path_boundary_match("/adminPanel", "/admin"));
        assert!(!url_path_boundary_match("/x/admin", "/admin"));
    }

    #[test]
    fn ip_match_canonicalizes_v4_mapped_ipv6() {
        let entry = IocEntry::new(
            IocType::Ip,
            "::ffff:203.0.113.10".to_string(),
            "fixture".to_string(),
            "medium".to_string(),
            String::new(),
            String::new(),
        )
        .unwrap();
        assert!(entry.matches("remote_ip", "203.0.113.10"));
        assert!(!entry.matches("remote_ip", "203.0.113.11"));

        let plain = IocEntry::new(
            IocType::Ip,
            "203.0.113.10".to_string(),
            "fixture".to_string(),
            "medium".to_string(),
            String::new(),
            String::new(),
        )
        .unwrap();
        assert!(plain.matches("remote_ip", "::ffff:203.0.113.10"));
    }

    #[test]
    fn csv_ioc_skips_bad_rows_and_keeps_loading() {
        let root = crate::unique_test_dir("ioc-csv");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("ioc.csv");
        fs::write(
            &path,
            "type,value\nip,203.0.113.10\ncidr,not-a-cidr\n,missing-value\n",
        )
        .unwrap();

        let loaded = load_ioc_file(&path).unwrap();

        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.skipped_rows, 2);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn short_hash_indicators_are_counted_for_warning() {
        let entries = [
            IocEntry::new(
                IocType::Hash,
                "a".repeat(32),
                "f".to_string(),
                "medium".to_string(),
                String::new(),
                String::new(),
            )
            .unwrap(),
            IocEntry::new(
                IocType::Hash,
                "b".repeat(40),
                "f".to_string(),
                "medium".to_string(),
                String::new(),
                String::new(),
            )
            .unwrap(),
            IocEntry::new(
                IocType::Hash,
                "c".repeat(64),
                "f".to_string(),
                "medium".to_string(),
                String::new(),
                String::new(),
            )
            .unwrap(),
        ];
        assert_eq!(short_hash_indicator_count(&entries), 2);
        // sha256 长度可正常比对,md5/sha1 长度直接不匹配。
        assert!(!entries[0].matches("file_sha256", &"c".repeat(64)));
        assert!(entries[2].matches("file_sha256", &"c".repeat(64)));
    }
}
