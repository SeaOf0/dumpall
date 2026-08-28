use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{
    AppLogEvent, DbLogEvent, Finding, HttpLogEvent, ScoreBreakdown, Severity, WafLogEvent,
};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use super::aggregations::{build_event_aggregations, five_minute_bucket, EventAggregation};
use super::allowlist::Allowlist;
use super::matcher::{event_field_with_aggregation, matches_record};
use super::rule_model::{parse_rule_set, DetectionRule, RuleSet};
use super::scoring::{score_for_rule, ScoreOutcome};

const EMBEDDED_BUILTIN_RULES_PATH: &str = "<embedded>/web_attack_builtin.yml";
const EMBEDDED_BUILTIN_RULES: &str = include_str!("../../rules/web_attack_builtin.yml");

#[derive(Debug, Default)]
pub struct DetectionReport {
    pub findings: Vec<Finding>,
    pub rules_loaded: usize,
    pub suppressed: usize,
    /// 检测阶段被时间窗口（event_cutoff/until）过滤掉的事件数（采集侧仍全量保留）。
    pub events_filtered_by_window: usize,
    /// 采集 jsonl 中无法反序列化的坏行数。
    pub malformed_rows: usize,
    /// 运行说明（allowlist 配置警告、窗口过滤等），供日志与上层 notes 使用。
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct DetectionRecord {
    rule_source: String,
    source_type: String,
    source_file: String,
    line_number: Option<u64>,
    default_field: String,
    raw_hash: Option<String>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FindingGroupKey {
    rule_id: String,
    source_file: String,
    remote_ip: String,
    uri_path: String,
    bucket: String,
}

#[derive(Debug, Clone)]
struct FindingAccumulator {
    rule_id: String,
    rule_name: String,
    category: String,
    source_type: String,
    source_file: Option<String>,
    line_number: Option<u64>,
    timestamp: Option<String>,
    remote_ip: Option<String>,
    method: Option<String>,
    uri_path: Option<String>,
    status: Option<u16>,
    raw_hash: Option<String>,
    recommendation: String,
    score: u16,
    severity: Severity,
    /// 规则声明的 severity（如 yml 的 severity: high）。
    rule_severity: Severity,
    score_breakdown: ScoreBreakdown,
    score_reasons: Vec<String>,
    match_count: usize,
}

/// 规则声明 severity 字符串 → Severity；未声明或无法识别返回 None。
fn declared_severity(rule: &DetectionRule) -> Option<Severity> {
    let value = rule.severity.as_deref()?.trim().to_ascii_lowercase();
    match value.as_str() {
        "info" | "informational" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "moderate" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// 取两者中较高的 severity（本地实现，不依赖 model 的排序派生）。
fn max_severity(score_severity: Severity, rule_severity: Severity) -> Severity {
    fn rank(severity: Severity) -> u8 {
        match severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
    if rank(score_severity) >= rank(rule_severity) {
        score_severity
    } else {
        rule_severity
    }
}

pub fn run_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<DetectionReport> {
    let rules = load_rules(&resolved.rules)?;
    let enabled_rules = rules.iter().filter(|rule| rule.enabled).count();
    logger.log(format!("detector: {} enabled rule(s)", enabled_rules))?;

    let allowlist = Allowlist::load(resolved.allowlist.as_deref())?;
    let mut notes = Vec::new();
    // allowlist 中无法解析的 IP/CIDR 条目不再静默失效：记入 notes 与日志。
    for warning in &allowlist.warnings {
        let line = format!("detector: allowlist warning: {warning}");
        logger.log(line.clone())?;
        notes.push(line);
    }

    let window = DetectionWindow::from_resolved(resolved);
    if window.active() {
        logger.log(format!(
            "detector: time window active (since {:?}, until {:?}); out-of-window events are excluded from matching only, collection stays full",
            window.since.map(|value| value.to_string()),
            window.until.map(|value| value.to_string())
        ))?;
    }
    let inputs = load_detection_records(layout, &window)?;
    let records = inputs.records;
    logger.log(format!(
        "detector: {} normalized record(s) available, {} event(s) excluded by time window, {} malformed jsonl row(s)",
        records.len(),
        inputs.events_filtered_by_window,
        inputs.malformed_rows
    ))?;
    if inputs.events_filtered_by_window > 0 {
        notes.push(format!(
            "detection: {} collected event(s) fell outside the requested time window and were excluded from alerting (collection output keeps them)",
            inputs.events_filtered_by_window
        ));
    }
    if inputs.malformed_rows > 0 {
        notes.push(format!(
            "detection: {} collected jsonl row(s) could not be parsed and were skipped",
            inputs.malformed_rows
        ));
    }

    let mut report = DetectionReport {
        rules_loaded: enabled_rules,
        events_filtered_by_window: inputs.events_filtered_by_window,
        malformed_rows: inputs.malformed_rows,
        notes,
        ..DetectionReport::default()
    };
    let mut groups: BTreeMap<FindingGroupKey, FindingAccumulator> = BTreeMap::new();

    for record in &records {
        for rule in &rules {
            if !rule.enabled || !rule.source.eq_ignore_ascii_case(&record.rule_source) {
                continue;
            }
            if !matches_record(&rule.matcher, &record.default_field, &|field| {
                record.field(field)
            }) {
                continue;
            }
            let allowlist_path = record.path_for_allowlist();
            let allowlist_ip = record.source_ip_for_allowlist();
            let allowlist_user_agent = record.field("user_agent");
            if allowlist.suppresses_values(
                rule,
                allowlist_path.as_deref(),
                allowlist_ip.as_deref(),
                allowlist_user_agent.as_deref(),
            ) {
                report.suppressed += 1;
                continue;
            }

            let score = score_for_rule(rule, &record.default_field, &|field| record.field(field));
            let key = FindingGroupKey::from_match(rule, record);
            groups
                .entry(key)
                .and_modify(|accumulator| accumulator.merge(record, &score))
                .or_insert_with(|| FindingAccumulator::new(rule, record, score));
        }
    }

    report.findings = groups
        .into_values()
        .enumerate()
        .map(|(index, accumulator)| accumulator.into_finding(index + 1))
        .collect();
    writers::write_findings_jsonl(&layout.findings_jsonl, &report.findings)?;
    writers::write_findings_csv(&layout.findings_csv, &report.findings)?;
    Ok(report)
}

pub fn load_rules(extra_paths: &[PathBuf]) -> Result<Vec<DetectionRule>> {
    let mut rules = Vec::new();
    for loaded in load_rule_sets(extra_paths)? {
        let rule_set = loaded.rule_set;
        rules.extend(rule_set.rules);
    }
    Ok(rules)
}

#[derive(Debug, Clone)]
pub struct LoadedRuleSet {
    pub path: PathBuf,
    pub sha256: String,
    pub rule_set: RuleSet,
    pub embedded: bool,
}

pub fn load_rule_sets(extra_paths: &[PathBuf]) -> Result<Vec<LoadedRuleSet>> {
    load_rule_sets_with_defaults(default_rule_paths(), extra_paths)
}

/// 加载规则文件：磁盘默认路径 + 用户 --rules 路径。
/// 关键行为：当磁盘默认路径一个都不存在（dist 裸二进制部署，CWD 无 rules/ 目录）时，
/// 无论 extra_paths 是否为空，嵌入式内置规则（EMBEDDED_BUILTIN_RULES）始终参与加载——
/// 与 CLI 承诺的 “--rules 与内置规则一起校验和执行” 一致，避免 --rules 传入导致
/// 内置 57 条规则整体静默失效（大面积漏报）。
/// 去重：路径 canonicalize 后 sort+dedup（同一文件经不同写法传入只加载一次，
/// canonicalize 失败时保留原值）；用户传入与内置内容完全相同的规则文件时按
/// sha256 去重，避免同内容双载。
pub(crate) fn load_rule_sets_with_defaults(
    defaults: Vec<PathBuf>,
    extra_paths: &[PathBuf],
) -> Result<Vec<LoadedRuleSet>> {
    let defaults_available = !defaults.is_empty();
    let mut files = defaults;
    files.extend(expand_rule_paths(extra_paths));
    let mut keyed: Vec<(PathBuf, PathBuf)> = files
        .into_iter()
        .map(|path| {
            let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            (key, path)
        })
        .collect();
    keyed.sort();
    keyed.dedup_by(|left, right| left.0 == right.0);

    let mut loaded = Vec::new();
    for (_, file) in keyed {
        let content = fs::read_to_string(&file)?;
        let rule_set = parse_rule_set(&content)?;
        loaded.push(LoadedRuleSet {
            path: file,
            sha256: sha256_hex(content.as_bytes()),
            rule_set,
            embedded: false,
        });
    }
    if !defaults_available {
        let embedded_sha = sha256_hex(EMBEDDED_BUILTIN_RULES.as_bytes());
        let already_loaded = loaded.iter().any(|item| item.sha256 == embedded_sha);
        if !already_loaded {
            loaded.push(LoadedRuleSet {
                path: PathBuf::from(EMBEDDED_BUILTIN_RULES_PATH),
                sha256: embedded_sha,
                rule_set: parse_rule_set(EMBEDDED_BUILTIN_RULES)?,
                embedded: true,
            });
        }
    }
    validate_rule_ids_across_files(&loaded)?;
    Ok(loaded)
}

/// 跨文件规则 ID 重复检测：任一 ID 在多个文件（含嵌入式内置）间重复时，
/// 返回 rule_validation 错误并列出重复 ID 与所在文件。
fn validate_rule_ids_across_files(loaded: &[LoadedRuleSet]) -> Result<()> {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    let mut duplicates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in loaded {
        for rule in &item.rule_set.rules {
            let path = item.path.to_string_lossy().into_owned();
            match owner.get(&rule.id) {
                Some(first_path) => {
                    duplicates
                        .entry(rule.id.clone())
                        .or_insert_with(|| vec![first_path.clone()])
                        .push(path);
                }
                None => {
                    owner.insert(rule.id.clone(), path);
                }
            }
        }
    }
    if !duplicates.is_empty() {
        let detail = duplicates
            .iter()
            .map(|(id, paths)| format!("{id}: {}", paths.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(crate::error::DumpallError::rule_validation(format!(
            "duplicate rule id(s) across rule files: {detail}"
        )));
    }
    Ok(())
}

pub fn validate_rule_file(path: &Path) -> Result<usize> {
    let content = fs::read_to_string(path)?;
    let rule_set = parse_rule_set(&content)?;
    Ok(rule_set.rules.len())
}

/// 检测阶段时间窗口（告警窄）：!full_scan 时按 event_cutoff（下界）与
/// time_range.until（上界，有则用）过滤事件后再匹配；无时间戳或时间解析失败的
/// 事件保守保留（证据优先）。采集侧 jsonl 仍全量（采集宽），此处只窄化告警。
#[derive(Debug, Clone, Copy)]
struct DetectionWindow {
    since: Option<time::OffsetDateTime>,
    until: Option<time::OffsetDateTime>,
}

impl DetectionWindow {
    fn from_resolved(resolved: &ResolvedRun) -> Self {
        if resolved.full_scan {
            return Self {
                since: None,
                until: None,
            };
        }
        let since = resolved
            .event_cutoff
            .as_deref()
            .and_then(|value| crate::time_utils::parse_datetime(value).ok());
        let until = resolved
            .time_range
            .until
            .as_deref()
            .and_then(|value| crate::time_utils::parse_datetime(value).ok());
        Self { since, until }
    }

    fn active(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    fn contains(&self, timestamp: Option<&str>) -> bool {
        let Some(timestamp) = timestamp else {
            return true;
        };
        let Ok(parsed) = crate::time_utils::parse_datetime(timestamp) else {
            return true;
        };
        if let Some(since) = self.since {
            if parsed < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if parsed > until {
                return false;
            }
        }
        true
    }
}

struct DetectionInputs {
    records: Vec<DetectionRecord>,
    events_filtered_by_window: usize,
    malformed_rows: usize,
}

fn load_detection_records(layout: &OutputLayout, window: &DetectionWindow) -> Result<DetectionInputs> {
    let mut events_filtered = 0usize;
    let mut malformed_rows = 0usize;

    let (events, filtered, malformed) = read_http_events(&layout.http_events, window)?;
    events_filtered += filtered;
    malformed_rows += malformed;
    // 5 分钟聚合只在通过窗口的事件内计算：窗外事件不应抬高窗口内事件的聚合计数。
    let aggregations = build_event_aggregations(&events);
    let mut records = events
        .iter()
        .zip(aggregations.iter())
        .map(|(event, aggregation)| DetectionRecord::from_event(event, aggregation))
        .collect::<Vec<_>>();

    records.extend(read_csv_records(
        &layout.processes,
        "process",
        "process",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.network_connections,
        "network",
        "network",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.scheduled_tasks,
        "persistence",
        "persistence",
        Some(("persistence_type", "scheduled_task")),
    )?);
    records.extend(read_csv_records(
        &layout.startup_items,
        "persistence",
        "persistence",
        Some(("persistence_type", "startup_item")),
    )?);
    records.extend(read_csv_records(
        &layout.services,
        "persistence",
        "persistence",
        Some(("persistence_type", "service")),
    )?);
    // ---- triage 扩展源（host artifacts）----
    records.extend(read_csv_records(
        &layout.shell_history,
        "shell_history",
        "shell_history",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.login_history,
        "login_history",
        "login_history",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.persistence_misc,
        "persistence",
        "persistence_misc",
        Some(("persistence_type", "misc")),
    )?);
    records.extend(read_csv_records(
        &layout.sudoers,
        "sudoers",
        "sudoers",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.ssh_keys,
        "ssh_keys",
        "ssh_keys",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.sshd_config_flags,
        "sshd_config",
        "sshd_config",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.firewall_rules,
        "firewall",
        "firewall",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.deleted_open_files,
        "deleted_open",
        "deleted_open",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.suid_files,
        "suid_file",
        "suid_file",
        None,
    )?);
    // 扩展数据源：内核参数、文件系统异常、二进制目录变更、已装软件包。
    records.extend(read_csv_records(
        &layout.kernel_params,
        "kernel_params",
        "kernel_params",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.fs_anomalies,
        "fs_anomaly",
        "fs_anomaly",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.bin_dir_changes,
        "bin_change",
        "bin_change",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.registry_persistence,
        "registry_persistence",
        "registry_persistence",
        None,
    )?);
    records.extend(read_csv_records(
        &layout.wmi_subscriptions,
        "wmi_subscription",
        "wmi_subscription",
        None,
    )?);
    let (db_records, filtered, malformed) = read_db_events(&layout.db_events, window)?;
    events_filtered += filtered;
    malformed_rows += malformed;
    records.extend(db_records);
    let (app_records, filtered, malformed) = read_app_events(&layout.app_events, window)?;
    events_filtered += filtered;
    malformed_rows += malformed;
    records.extend(app_records);
    let (waf_records, filtered, malformed) = read_waf_events(&layout.waf_events, window)?;
    events_filtered += filtered;
    malformed_rows += malformed;
    records.extend(waf_records);

    Ok(DetectionInputs {
        records,
        events_filtered_by_window: events_filtered,
        malformed_rows,
    })
}

/// 读入 http 事件 jsonl，返回 (事件, 被时间窗口过滤数, 坏行数)。
/// 坏行（反序列化失败）计数并跳过，不再静默丢弃。
fn read_http_events(
    path: &Path,
    window: &DetectionWindow,
) -> Result<(Vec<HttpLogEvent>, usize, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0, 0));
    }
    let content = fs::read_to_string(path)?;
    let mut events = Vec::new();
    let mut filtered = 0usize;
    let mut malformed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<HttpLogEvent>(line) else {
            malformed += 1;
            continue;
        };
        if !window.contains(event.timestamp.as_deref()) {
            filtered += 1;
            continue;
        }
        events.push(event);
    }
    Ok((events, filtered, malformed))
}

fn read_db_events(
    path: &Path,
    window: &DetectionWindow,
) -> Result<(Vec<DetectionRecord>, usize, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0, 0));
    }
    let content = fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut filtered = 0usize;
    let mut malformed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<DbLogEvent>(line) else {
            malformed += 1;
            continue;
        };
        if !window.contains(event.timestamp.as_deref()) {
            filtered += 1;
            continue;
        }
        records.push(DetectionRecord::from_db_event(&event));
    }
    Ok((records, filtered, malformed))
}

fn read_app_events(
    path: &Path,
    window: &DetectionWindow,
) -> Result<(Vec<DetectionRecord>, usize, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0, 0));
    }
    let content = fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut filtered = 0usize;
    let mut malformed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<AppLogEvent>(line) else {
            malformed += 1;
            continue;
        };
        if !window.contains(event.timestamp.as_deref()) {
            filtered += 1;
            continue;
        }
        records.push(DetectionRecord::from_app_event(&event));
    }
    Ok((records, filtered, malformed))
}

fn read_waf_events(
    path: &Path,
    window: &DetectionWindow,
) -> Result<(Vec<DetectionRecord>, usize, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), 0, 0));
    }
    let content = fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut filtered = 0usize;
    let mut malformed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<WafLogEvent>(line) else {
            malformed += 1;
            continue;
        };
        if !window.contains(event.timestamp.as_deref()) {
            filtered += 1;
            continue;
        }
        records.push(DetectionRecord::from_waf_event(&event));
    }
    Ok((records, filtered, malformed))
}

fn read_csv_records(
    path: &Path,
    rule_source: &str,
    source_type: &str,
    extra: Option<(&str, &str)>,
) -> Result<Vec<DetectionRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
    let headers = reader.headers()?.clone();
    let mut records = Vec::new();

    for (index, row) in reader.records().enumerate() {
        let Ok(row) = row else {
            continue;
        };
        let mut fields = BTreeMap::new();
        for (header, value) in headers.iter().zip(row.iter()) {
            insert_field(&mut fields, header, value);
        }
        if let Some((key, value)) = extra {
            insert_field(&mut fields, key, value);
        }
        add_csv_aliases(&mut fields);
        let record_text = fields
            .values()
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if record_text.trim().is_empty() {
            continue;
        }
        insert_field(&mut fields, "record", &record_text);
        insert_field(&mut fields, "source_file", &path.display().to_string());
        insert_field(&mut fields, "line_number", &(index as u64 + 2).to_string());

        records.push(DetectionRecord {
            rule_source: rule_source.to_string(),
            source_type: source_type.to_string(),
            source_file: path.display().to_string(),
            line_number: Some(index as u64 + 2),
            default_field: "record".to_string(),
            raw_hash: Some(sha256_hex(record_text.as_bytes())),
            fields,
        });
    }

    Ok(records)
}

fn insert_field(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    fields.insert(normalize_field_name(key), value.trim().to_string());
}

fn normalize_field_name(key: &str) -> String {
    key.trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .replace(['-', ' '], "_")
}

fn add_csv_aliases(fields: &mut BTreeMap<String, String>) {
    if let Some(value) = fields.get("command_line").cloned() {
        fields.entry("command".to_string()).or_insert(value);
    }
    if let Some(value) = fields.get("executable_path").cloned() {
        fields.entry("path".to_string()).or_insert(value);
    }
    if let Some(value) = fields.get("remote_address").cloned() {
        fields.entry("remote_ip".to_string()).or_insert(value);
    }
    if let Some(value) = fields.get("sc_status").cloned() {
        fields.entry("status".to_string()).or_insert(value);
    }
}

impl DetectionRecord {
    fn from_event(event: &HttpLogEvent, aggregation: &EventAggregation) -> Self {
        let mut fields = BTreeMap::new();
        for field in [
            "timestamp",
            "source_file",
            "line_number",
            "remote_ip",
            "logged_remote_ip",
            "xff_ip",
            "inferred_client_ip",
            "proxy_ip",
            "client_ip_source",
            "method",
            "scheme",
            "host",
            "uri_path",
            "uri_query",
            "uri",
            "status",
            "bytes_sent",
            "referer",
            "user_agent",
            "request_time",
            "upstream_status",
            "upstream_time",
            "parser_name",
            "raw_hash",
            "request",
            "same_ip_request_count_5m",
            "same_ip_same_path_count_5m",
            "same_ip_404_count_5m",
            "same_ip_login_fail_count_5m",
        ] {
            if let Some(value) = event_field_with_aggregation(event, Some(aggregation), field) {
                insert_field(&mut fields, field, &value);
            }
        }
        // 时间缺失/不可解析的事件不产生 5 分钟桶字段（不并入 0 桶），
        // 分组时退回行号桶，避免无时间事件被跨时间聚合计数。
        if let Some(bucket) = five_minute_bucket(event) {
            insert_field(&mut fields, "time_bucket_5m", &bucket.to_string());
        }

        Self {
            rule_source: "http_access".to_string(),
            source_type: "access_log".to_string(),
            source_file: event.source_file.clone(),
            line_number: Some(event.line_number),
            default_field: "request".to_string(),
            raw_hash: Some(event.raw_hash.clone()),
            fields,
        }
    }

    fn from_db_event(event: &DbLogEvent) -> Self {
        let mut fields = BTreeMap::new();
        for (field, value) in [
            ("timestamp", event.timestamp.clone()),
            ("source_file", Some(event.source_file.clone())),
            ("line_number", Some(event.line_number.to_string())),
            ("db_type", Some(event.db_type.clone())),
            ("db_instance", event.db_instance.clone()),
            ("db_user", event.db_user.clone()),
            ("db_name", event.db_name.clone()),
            ("client_ip", event.client_ip.clone()),
            (
                "client_port",
                event.client_port.map(|port| port.to_string()),
            ),
            ("session_id", event.session_id.clone()),
            ("statement_type", event.statement_type.clone()),
            ("statement_summary", event.statement_summary.clone()),
            (
                "duration_ms",
                event.duration_ms.map(|duration| duration.to_string()),
            ),
            ("rows", event.rows.map(|rows| rows.to_string())),
            ("error_code", event.error_code.clone()),
            ("severity", event.severity.clone()),
            ("raw_hash", Some(event.raw_hash.clone())),
        ] {
            if let Some(value) = value {
                insert_field(&mut fields, field, &value);
            }
        }
        let record_text = [
            event.db_type.as_str(),
            event.db_user.as_deref().unwrap_or_default(),
            event.db_name.as_deref().unwrap_or_default(),
            event.client_ip.as_deref().unwrap_or_default(),
            event.statement_type.as_deref().unwrap_or_default(),
            event.statement_summary.as_deref().unwrap_or_default(),
        ]
        .join(" ");
        insert_field(&mut fields, "record", &record_text);
        insert_field(
            &mut fields,
            "remote_ip",
            event.client_ip.as_deref().unwrap_or_default(),
        );

        Self {
            rule_source: "db_log".to_string(),
            source_type: "db_log".to_string(),
            source_file: event.source_file.clone(),
            line_number: Some(event.line_number),
            default_field: "statement_summary".to_string(),
            raw_hash: Some(event.raw_hash.clone()),
            fields,
        }
    }

    fn from_app_event(event: &AppLogEvent) -> Self {
        let mut fields = BTreeMap::new();
        for (field, value) in [
            ("timestamp", event.timestamp.clone()),
            ("source_file", Some(event.source_file.clone())),
            ("line_number", Some(event.line_number.to_string())),
            ("framework", event.framework.clone()),
            ("level", event.level.clone()),
            ("logger", event.logger.clone()),
            ("exception_type", event.exception_type.clone()),
            ("message_summary", event.message_summary.clone()),
            ("request_id", event.request_id.clone()),
            ("trace_id", event.trace_id.clone()),
            ("http_path", event.http_path.clone()),
            ("uri_path", event.http_path.clone()),
            ("user_summary", event.user_summary.clone()),
            ("raw_hash", Some(event.raw_hash.clone())),
        ] {
            if let Some(value) = value {
                insert_field(&mut fields, field, &value);
            }
        }
        let record_text = [
            event.framework.as_deref().unwrap_or_default(),
            event.level.as_deref().unwrap_or_default(),
            event.logger.as_deref().unwrap_or_default(),
            event.exception_type.as_deref().unwrap_or_default(),
            event.message_summary.as_deref().unwrap_or_default(),
            event.http_path.as_deref().unwrap_or_default(),
        ]
        .join(" ");
        insert_field(&mut fields, "record", &record_text);

        Self {
            rule_source: "app_log".to_string(),
            source_type: "app_log".to_string(),
            source_file: event.source_file.clone(),
            line_number: Some(event.line_number),
            default_field: "message_summary".to_string(),
            raw_hash: Some(event.raw_hash.clone()),
            fields,
        }
    }

    fn from_waf_event(event: &WafLogEvent) -> Self {
        let mut fields = BTreeMap::new();
        for (field, value) in [
            ("timestamp", event.timestamp.clone()),
            ("source_file", Some(event.source_file.clone())),
            ("line_number", Some(event.line_number.to_string())),
            ("vendor", event.vendor.clone()),
            ("action", event.action.clone()),
            ("waf_rule_id", event.rule_id.clone()),
            ("waf_rule_name", event.rule_name.clone()),
            ("client_ip", event.client_ip.clone()),
            ("remote_ip", event.client_ip.clone()),
            ("proxy_ip", event.proxy_ip.clone()),
            ("host", event.host.clone()),
            ("method", event.method.clone()),
            ("path", event.path.clone()),
            ("uri_path", event.path.clone()),
            ("status", event.status.map(|status| status.to_string())),
            ("waf_score", event.score.map(|score| score.to_string())),
            ("raw_hash", Some(event.raw_hash.clone())),
        ] {
            if let Some(value) = value {
                insert_field(&mut fields, field, &value);
            }
        }
        let record_text = [
            event.vendor.as_deref().unwrap_or_default(),
            event.action.as_deref().unwrap_or_default(),
            event.rule_id.as_deref().unwrap_or_default(),
            event.rule_name.as_deref().unwrap_or_default(),
            event.client_ip.as_deref().unwrap_or_default(),
            event.host.as_deref().unwrap_or_default(),
            event.method.as_deref().unwrap_or_default(),
            event.path.as_deref().unwrap_or_default(),
        ]
        .join(" ");
        insert_field(&mut fields, "record", &record_text);

        Self {
            rule_source: "waf_log".to_string(),
            source_type: "waf_log".to_string(),
            source_file: event.source_file.clone(),
            line_number: Some(event.line_number),
            default_field: "record".to_string(),
            raw_hash: Some(event.raw_hash.clone()),
            fields,
        }
    }

    fn field(&self, field: &str) -> Option<String> {
        self.fields.get(&normalize_field_name(field)).cloned()
    }

    fn path_for_allowlist(&self) -> Option<String> {
        self.field("uri_path").or_else(|| self.field("path"))
    }

    fn source_ip_for_allowlist(&self) -> Option<String> {
        self.field("remote_ip").or_else(|| self.field("source_ip"))
    }

    fn status(&self) -> Option<u16> {
        self.field("status")
            .and_then(|value| value.parse::<u16>().ok())
    }
}

impl FindingGroupKey {
    fn from_match(rule: &DetectionRule, record: &DetectionRecord) -> Self {
        // 有时间戳的 http 事件按 5 分钟桶聚合；无时间戳事件（含 http）退回行号桶，
        // 不再并入统一的 "0" 桶，防止无时间数据把计数膨胀到全量。
        let bucket = record
            .field("time_bucket_5m")
            .or_else(|| record.line_number.map(|line| line.to_string()))
            .unwrap_or_else(|| "record".to_string());

        Self {
            rule_id: rule.id.clone(),
            source_file: record.source_file.clone(),
            remote_ip: record
                .field("remote_ip")
                .or_else(|| record.field("client_ip"))
                .unwrap_or_default(),
            uri_path: record
                .field("uri_path")
                .or_else(|| record.field("path"))
                .or_else(|| record.field("http_path"))
                .or_else(|| record.field("statement_type"))
                .unwrap_or_default(),
            bucket,
        }
    }
}

impl FindingAccumulator {
    fn new(rule: &DetectionRule, record: &DetectionRecord, score: ScoreOutcome) -> Self {
        Self {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            category: rule.category.clone(),
            source_type: record.source_type.clone(),
            source_file: Some(record.source_file.clone()),
            line_number: record.line_number,
            timestamp: record
                .field("timestamp")
                .or_else(|| record.field("started_at"))
                .or_else(|| record.field("modified_at"))
                .or_else(|| record.field("logon_time")),
            remote_ip: record.field("remote_ip").or_else(|| record.field("client_ip")),
            method: record.field("method"),
            uri_path: record
                .field("uri_path")
                .or_else(|| record.field("path"))
                .or_else(|| record.field("http_path"))
                .or_else(|| record.field("statement_type")),
            status: record.status(),
            raw_hash: record.raw_hash.clone(),
            recommendation: rule.recommendation.clone().unwrap_or_else(|| {
                "Review the source evidence, adjacent timeline, and host context before drawing conclusions."
                    .to_string()
            }),
            score: score.value,
            severity: score.severity,
            rule_severity: declared_severity(rule).unwrap_or(score.severity),
            score_breakdown: score.breakdown,
            score_reasons: score.reasons,
            match_count: 1,
        }
    }

    fn merge(&mut self, record: &DetectionRecord, score: &ScoreOutcome) {
        self.match_count += 1;
        if score.value > self.score {
            self.score = score.value;
            self.severity = score.severity;
            self.score_breakdown = score.breakdown.clone();
            self.score_reasons.clone_from(&score.reasons);
            self.raw_hash.clone_from(&record.raw_hash);
            self.line_number = record.line_number;
        }
    }

    fn into_finding(self, index: usize) -> Finding {
        let evidence_summary = self.evidence_summary();
        // severity 死字段接线：最终 severity 取分数推导值与规则声明值的较高者。
        let severity = max_severity(self.severity, self.rule_severity);
        Finding {
            finding_id: format!("F-{index:06}"),
            timestamp: self.timestamp,
            severity,
            score: self.score,
            confidence: crate::model::confidence_for(
                self.score,
                crate::model::default_evidence_quality_for_source(&self.source_type),
            ),
            evidence_quality: crate::model::default_evidence_quality_for_source(&self.source_type),
            evidence_quality_basis: String::new(),
            score_breakdown: self.score_breakdown,
            category: self.category,
            rule_id: self.rule_id,
            rule_name: self.rule_name,
            source_type: self.source_type,
            source_file: self.source_file,
            line_number: self.line_number,
            remote_ip: self.remote_ip,
            method: self.method,
            uri_path: self.uri_path,
            status: self.status,
            evidence_summary,
            raw_hash: self.raw_hash,
            related_ids: Vec::new(),
            evidence_chain_level: None,
            evidence_chain_basis: None,
            recommendation: self.recommendation,
        }
        .with_default_assessment()
    }

    fn evidence_summary(&self) -> String {
        let mut summary = format!(
            "Rule {} matched suspicious evidence in {}",
            self.rule_id, self.source_type
        );
        if let Some(source_file) = &self.source_file {
            summary.push_str(&format!(" from {source_file}"));
        }
        if let Some(line_number) = self.line_number {
            summary.push_str(&format!(" line {line_number}"));
        }
        if self.match_count > 1 {
            summary.push_str(&format!(
                "; aggregated {} matching records",
                self.match_count
            ));
        }
        if let Some(method) = &self.method {
            summary.push_str(&format!("; method {method}"));
        }
        if let Some(path) = &self.uri_path {
            summary.push_str(&format!("; path {path}"));
        }
        if let Some(status) = self.status {
            summary.push_str(&format!("; status {status}"));
        }
        if !self.score_reasons.is_empty() {
            summary.push_str(&format!(
                "; score reasons: {}",
                self.score_reasons.join("; ")
            ));
        }
        summary.push_str(". Treat as suspicious evidence, not proof of compromise.");
        summary
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

pub fn default_rule_paths() -> Vec<PathBuf> {
    [
        PathBuf::from("rules/web_attack_builtin.yml"),
        PathBuf::from("dumpall/rules/web_attack_builtin.yml"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
}

pub fn expand_rule_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            collect_yaml_files(path, &mut files);
        } else {
            files.push(path.clone());
        }
    }
    files.sort();
    files
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        files.push(dir.to_path_buf());
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| matches!(extension, "yml" | "yaml"))
            .unwrap_or(false);
        if is_yaml {
            files.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::aggregations::EventAggregation;
    use crate::detectors::matcher::matches_event_with_aggregation;

    #[test]
    fn builtin_rules_load_and_match_sqli_fixture() {
        let rules = load_rules(&[]).unwrap();
        let sqli = rules.iter().find(|rule| rule.id == "WEB-SQLI-001").unwrap();
        let event = HttpLogEvent {
            timestamp: Some("2026-05-15T00:00:00Z".to_string()),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some("203.0.113.1".to_string()),
            xff_ip: None,
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("GET".to_string()),
            scheme: None,
            host: None,
            uri_path: Some("/search".to_string()),
            uri_query: Some("q=1%20UNION%20SELECT%20password".to_string()),
            status: Some(200),
            bytes_sent: Some(1),
            referer: None,
            user_agent: Some("test".to_string()),
            request_time: None,
            upstream_status: None,
            upstream_time: None,
            raw_hash: "hash".to_string(),
            parser_name: "test".to_string(),
            parse_confidence: 1.0,
        };

        assert!(matches_event_with_aggregation(
            &sqli.matcher,
            &event,
            Some(&EventAggregation {
                same_ip_same_path_count_5m: 3,
                ..EventAggregation::default()
            })
        ));
    }

    /// dist 场景（磁盘默认路径一个都不存在）下，即使传了 --rules，
    /// 嵌入式内置规则也必须参与加载（与 CLI 承诺一致）。
    #[test]
    fn embedded_builtin_rules_load_with_extra_rules_in_dist_layout() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-rules-dist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let extra = dir.join("custom.yml");
        std::fs::write(
            &extra,
            "schema_version: 1\nrules:\n  - id: CUSTOM-TEST-001\n    name: custom\n    category: test\n    source: http_access\n    match:\n      contains: \"probe-token\"\n",
        )
        .unwrap();

        let loaded = load_rule_sets_with_defaults(Vec::new(), &[extra.clone()]).unwrap();
        assert_eq!(loaded.len(), 2, "embedded builtin + user rule file");
        assert!(
            loaded
                .iter()
                .any(|item| item.embedded && item.path == PathBuf::from(EMBEDDED_BUILTIN_RULES_PATH))
        );
        assert!(loaded.iter().any(|item| item.path == extra));
        let total_rules: usize = loaded.iter().map(|item| item.rule_set.rules.len()).sum();
        assert!(total_rules >= 57, "builtin 57 rules plus the custom one");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 用户 --rules 指向与默认路径相同的文件时按 canonicalize 去重，不双载。
    #[test]
    fn same_file_via_default_and_extra_loads_once() {
        let default =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/web_attack_builtin.yml");
        let loaded =
            load_rule_sets_with_defaults(vec![default.clone()], &[default.clone()]).unwrap();
        assert_eq!(loaded.len(), 1, "duplicate path must load once");
    }

    /// 用户传入与内置内容完全相同的文件时按 sha 去重，内置不再重复加载。
    #[test]
    fn builtin_content_via_extra_path_does_not_double_load() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-rules-copy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("builtin_copy.yml");
        std::fs::write(&copy, EMBEDDED_BUILTIN_RULES).unwrap();

        let loaded = load_rule_sets_with_defaults(Vec::new(), &[copy]).unwrap();
        assert_eq!(loaded.len(), 1, "identical content must load once");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// 跨文件重复 ID 必须报 rule_validation 错误并列出 ID 与文件。
    #[test]
    fn duplicate_rule_ids_across_files_are_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-rules-dup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let extra = dir.join("dup.yml");
        std::fs::write(
            &extra,
            "schema_version: 1\nrules:\n  - id: WEB-SQLI-001\n    name: duplicate of builtin\n    category: sqli\n    source: http_access\n    match:\n      contains: \"union\"\n",
        )
        .unwrap();

        let error = load_rule_sets_with_defaults(Vec::new(), &[extra.clone()])
            .err()
            .expect("duplicate ids must fail");
        let message = error.to_string();
        assert!(message.contains("WEB-SQLI-001"), "{message}");
        assert!(message.contains("duplicate"), "{message}");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// WEB-BRUTE-001 的失败口径与 aggregations 一致：302（PRG 正常登录成功跳转）
    /// 不再计失败；401/403/429 仍计。
    #[test]
    fn web_brute_001_excludes_302_from_failure_statuses() {
        let rules = load_rules(&[]).unwrap();
        let brute = rules
            .iter()
            .find(|rule| rule.id == "WEB-BRUTE-001")
            .unwrap();

        let login_event = |status: u16| HttpLogEvent {
            timestamp: Some("2026-05-15T08:00:00Z".to_string()),
            source_file: "access.log".to_string(),
            line_number: 1,
            remote_ip: Some("203.0.113.1".to_string()),
            xff_ip: None,
            inferred_client_ip: None,
            proxy_ip: None,
            client_ip_source: None,
            method: Some("POST".to_string()),
            scheme: None,
            host: None,
            uri_path: Some("/login".to_string()),
            uri_query: Some("user=admin".to_string()),
            status: Some(status),
            bytes_sent: Some(1),
            referer: None,
            user_agent: Some("test".to_string()),
            request_time: None,
            upstream_status: None,
            upstream_time: None,
            raw_hash: "hash".to_string(),
            parser_name: "test".to_string(),
            parse_confidence: 1.0,
        };

        assert!(!matches_event_with_aggregation(
            &brute.matcher,
            &login_event(302),
            None
        ));
        for status in [401u16, 403, 429] {
            assert!(
                matches_event_with_aggregation(&brute.matcher, &login_event(status), None),
                "status {status} must stay a failure"
            );
        }
    }

    #[test]
    fn detection_window_filters_old_and_future_events_but_keeps_untimestamped() {
        let window = DetectionWindow {
            since: crate::time_utils::parse_datetime("2026-05-15T08:00:00Z").ok(),
            until: crate::time_utils::parse_datetime("2026-05-15T09:00:00Z").ok(),
        };
        assert!(!window.contains(Some("2026-05-15T07:59:59Z"))); // 早于下界
        assert!(window.contains(Some("2026-05-15T08:00:00Z"))); // 恰在下界
        assert!(window.contains(Some("2026-05-15T08:30:00Z")));
        assert!(!window.contains(Some("2026-05-15T09:00:01Z"))); // 晚于上界
        assert!(window.contains(None)); // 无时间戳保守保留
        assert!(window.contains(Some("not-a-time"))); // 解析失败保守保留

        let full = DetectionWindow {
            since: None,
            until: None,
        };
        assert!(!full.active());
        assert!(full.contains(Some("1999-01-01T00:00:00Z")));
    }
}
