use crate::collector_trait::{
    path_strings, CollectOutput, CollectPlan, Collector, Discovery, ResourceBudget,
};
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{CollectionError, LinuxEvent, ParseError, WindowsEvent};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use serde::Serialize;

pub mod journald;
pub mod linux_audit;
pub mod windows_evtx;

pub struct EventsCollector;

impl Collector for EventsCollector {
    fn name(&self) -> &'static str {
        "events"
    }

    fn discover(&self, ctx: &ResolvedRun) -> Result<Vec<Discovery>> {
        let mut rows = Vec::new();
        for path in &ctx.evtx_paths {
            rows.push(Discovery {
                collector: self.name().to_string(),
                kind: "windows_evtx".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "user supplied --evtx-path".to_string(),
            });
        }
        for path in &ctx.journal_paths {
            rows.push(Discovery {
                collector: self.name().to_string(),
                kind: "journald".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "user supplied --journal-path".to_string(),
            });
        }
        for path in &ctx.audit_log_paths {
            rows.push(Discovery {
                collector: self.name().to_string(),
                kind: "audit_log".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "user supplied --audit-log-path".to_string(),
            });
        }
        Ok(rows)
    }

    fn plan(&self, ctx: &ResolvedRun, discoveries: &[Discovery]) -> Result<CollectPlan> {
        let mut inputs = discoveries
            .iter()
            .filter_map(|discovery| discovery.path.clone())
            .collect::<Vec<_>>();
        if inputs.is_empty() && ctx.host_events_enabled() {
            inputs.push("host event defaults with time and record limits".to_string());
        }

        Ok(CollectPlan {
            collector: self.name().to_string(),
            enabled: ctx.host_events_enabled(),
            readonly: true,
            dry_run_supported: true,
            active_check_allowed: false,
            summary: if ctx.host_events_enabled() {
                "Plan Windows EVTX and Linux auditd/journald event summaries with bounded record parsing.".to_string()
            } else {
                "Host event collector disabled for this profile.".to_string()
            },
            inputs,
            outputs: vec![
                "events/windows_events.jsonl".to_string(),
                "events/linux_events.jsonl".to_string(),
                "events/auth_events.csv".to_string(),
                "events/process_events.csv".to_string(),
                "events/service_events.csv".to_string(),
                "events/scheduled_task_events.csv".to_string(),
                "events/powershell_events.csv".to_string(),
                "events/event_parse_errors.csv".to_string(),
            ],
            budget: ResourceBudget {
                max_files: None,
                max_records: Some(ctx.max_event_records),
                max_file_size_mb: Some(ctx.safety.max_file_size_mb),
                active_check_allowed: false,
            },
        })
    }

    fn collect(&self, _ctx: &ResolvedRun, plan: &CollectPlan) -> Result<CollectOutput> {
        Ok(CollectOutput {
            collector: self.name().to_string(),
            files_scanned: 0,
            records_emitted: 0,
            notes: vec![format!(
                "{} is planned for implementation; M0 only establishes the collector contract.",
                plan.collector
            )],
            errors: Vec::new(),
        })
    }
}

pub fn manual_inputs(ctx: &ResolvedRun) -> Vec<String> {
    let mut paths = Vec::new();
    paths.extend(path_strings(&ctx.evtx_paths));
    paths.extend(path_strings(&ctx.journal_paths));
    paths.extend(path_strings(&ctx.audit_log_paths));
    paths
}

#[derive(Debug, Default)]
pub struct EventsCollectionReport {
    pub files_scanned: u64,
    pub records_emitted: u64,
    pub lines_seen: u64,
    pub window_filtered: u64,
    pub errors: Vec<CollectionError>,
    pub parse_errors: Vec<ParseError>,
    pub notes: Vec<String>,
}

#[derive(Debug, Default)]
struct EventInventory {
    windows_events: Vec<WindowsEvent>,
    linux_events: Vec<LinuxEvent>,
    auth_rows: Vec<AuthEventRow>,
    process_rows: Vec<ProcessEventRow>,
    service_rows: Vec<ServiceEventRow>,
    scheduled_task_rows: Vec<ScheduledTaskEventRow>,
    powershell_rows: Vec<PowerShellEventRow>,
    parse_errors: Vec<ParseError>,
    errors: Vec<CollectionError>,
    files_scanned: u64,
    lines_seen: u64,
    window_filtered: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AuthEventRow {
    event_id: String,
    timestamp: String,
    source: String,
    user: String,
    source_ip: String,
    target_user: String,
    result: String,
    raw_hash: String,
    parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessEventRow {
    event_id: String,
    timestamp: String,
    source: String,
    process_name: String,
    process_id: String,
    parent_process_name: String,
    command_line_summary: String,
    user: String,
    raw_hash: String,
    parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceEventRow {
    event_id: String,
    timestamp: String,
    source: String,
    service_name: String,
    action: String,
    path: String,
    user: String,
    raw_hash: String,
    parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
struct ScheduledTaskEventRow {
    event_id: String,
    timestamp: String,
    source: String,
    task_name: String,
    action: String,
    command: String,
    user: String,
    raw_hash: String,
    parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
struct PowerShellEventRow {
    event_id: String,
    timestamp: String,
    source: String,
    script_summary: String,
    user: String,
    process_id: String,
    raw_hash: String,
    parser_confidence: f32,
}

/// 事件采集窗口（--log-days/--since 下界 + --until 上界；--full-scan 全量）。
/// 三条采集路径（EVTX 文本/二进制、audit/auth 文本、journald 导出）在读取循环内
/// 逐条调用 `contains` 边读边过滤：只有窗口内事件消耗 --max-event-records 配额，
/// 避免旧记录先把配额耗尽而事发时段（最新）记录从未被读取。
/// 无时间戳或解析失败的事件保守保留（证据优先），仅按可解析时间剔除窗外记录。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EventWindow {
    since: Option<time::OffsetDateTime>,
    until: Option<time::OffsetDateTime>,
}

impl EventWindow {
    pub(crate) fn from_resolved(resolved: &ResolvedRun) -> Self {
        let since = resolved
            .event_cutoff
            .as_deref()
            .and_then(|value| crate::time_utils::parse_datetime(value).ok());
        let until = resolved
            .time_range
            .until
            .as_deref()
            .filter(|_| !resolved.full_scan)
            .and_then(|value| crate::time_utils::parse_datetime(value).ok());
        Self { since, until }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    pub(crate) fn contains(&self, timestamp: Option<&str>) -> bool {
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

/// 单条事件窗口判定（语义：None/不可解析时间戳保守保留；full_scan 时 until 不生效）。
/// 采集循环按性能优先使用 `EventWindow::contains`（窗口只解析一次）；
/// 本函数是同语义的一次性便捷入口，供单条判定场景与测试使用。
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn event_in_window(resolved: &ResolvedRun, timestamp: Option<&str>) -> bool {
    EventWindow::from_resolved(resolved).contains(timestamp)
}

/// 采集完成后的兜底窗口过滤；正常情况下三条采集路径已边读边过滤，
/// 这里只承担历史遗留路径与防御性兜底，并统计兜底剔除数量。
fn apply_event_window(resolved: &ResolvedRun, inventory: &mut EventInventory) {
    let window = EventWindow::from_resolved(resolved);
    if !window.is_active() {
        return;
    }
    let before = inventory.windows_events.len() + inventory.linux_events.len();
    inventory
        .windows_events
        .retain(|event| window.contains(event.timestamp.as_deref()));
    inventory
        .linux_events
        .retain(|event| window.contains(event.timestamp.as_deref()));
    let after = inventory.windows_events.len() + inventory.linux_events.len();
    inventory.window_filtered += (before - after) as u64;
}

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<EventsCollectionReport> {
    logger.log("collector: host event sources")?;
    let mut inventory = EventInventory::default();

    if !resolved.evtx_paths.is_empty() {
        let windows = windows_evtx::collect_windows_events(resolved);
        inventory.files_scanned += windows.files_scanned;
        inventory.lines_seen += windows.lines_seen;
        inventory.errors.extend(windows.errors);
        inventory.parse_errors.extend(windows.parse_errors);
        inventory.window_filtered += windows.window_filtered;
        inventory.windows_events.extend(windows.events);
    }
    if !resolved.audit_log_paths.is_empty() {
        let linux = linux_audit::collect_linux_audit(resolved);
        inventory.files_scanned += linux.files_scanned;
        inventory.lines_seen += linux.lines_seen;
        inventory.errors.extend(linux.errors);
        inventory.parse_errors.extend(linux.parse_errors);
        inventory.window_filtered += linux.window_filtered;
        inventory.linux_events.extend(linux.events);
    }
    if !resolved.journal_paths.is_empty() {
        let journal = journald::collect_journald(resolved);
        inventory.files_scanned += journal.files_scanned;
        inventory.lines_seen += journal.lines_seen;
        inventory.errors.extend(journal.errors);
        inventory.parse_errors.extend(journal.parse_errors);
        inventory.window_filtered += journal.window_filtered;
        inventory.linux_events.extend(journal.events);
    }

    // journald-only 发行版（无 auth.log/secure/audit 文本源，如新版 Kali/Ubuntu）
    // 的兜底：live 模式下自动只读导出 auth/authpriv 设施日志并走同一解析路径。
    #[cfg(unix)]
    if (!has_readable_audit_input(&resolved.audit_log_paths))
        && resolved.journal_paths.is_empty()
        && resolved.mode != crate::model::RunMode::Analyze
    {
        if let Some(path) = linux_audit::export_journald_auth(
            layout,
            resolved.event_cutoff.as_deref(),
            &mut inventory.errors,
        ) {
            let exported = linux_audit::collect_linux_audit_for(&[path], resolved);
            inventory.files_scanned += exported.files_scanned;
            inventory.lines_seen += exported.lines_seen;
            inventory.errors.extend(exported.errors);
            inventory.parse_errors.extend(exported.parse_errors);
            inventory.window_filtered += exported.window_filtered;
            inventory.linux_events.extend(exported.events);
        }
    }

    apply_event_window(resolved, &mut inventory);

    build_summary_rows(&mut inventory);
    write_event_inventory(layout, &inventory)?;

    let records_emitted = inventory.windows_events.len()
        + inventory.linux_events.len()
        + inventory.auth_rows.len()
        + inventory.process_rows.len()
        + inventory.service_rows.len()
        + inventory.scheduled_task_rows.len()
        + inventory.powershell_rows.len();
    let parse_error_count = inventory.parse_errors.len();
    let window_filtered = inventory.window_filtered;
    let mut notes = vec![format!(
        "host event collection completed: {} Windows event row(s), {} Linux event row(s), {} summary row(s), {} parse error(s).",
        inventory.windows_events.len(),
        inventory.linux_events.len(),
        records_emitted
            .saturating_sub(inventory.windows_events.len())
            .saturating_sub(inventory.linux_events.len()),
        parse_error_count
    )];
    if window_filtered > 0 {
        notes.push(format!(
            "{window_filtered} event record(s) outside the configured time window were skipped during collection (in-window records only consume the max-event-records quota)."
        ));
    }
    Ok(EventsCollectionReport {
        files_scanned: inventory.files_scanned,
        records_emitted: records_emitted as u64,
        lines_seen: inventory.lines_seen,
        window_filtered,
        errors: inventory.errors,
        parse_errors: inventory.parse_errors,
        notes,
    })
}

#[cfg(unix)]
fn has_readable_audit_input(paths: &[std::path::PathBuf]) -> bool {
    paths.iter().any(|path| {
        if path.is_file() {
            return std::fs::metadata(path)
                .map(|meta| meta.len() > 0)
                .unwrap_or(false);
        }
        if !path.is_dir() {
            return false;
        }
        std::fs::read_dir(path)
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_type()
                        .map(|kind| kind.is_file())
                        .unwrap_or(false)
                        && entry.metadata().map(|meta| meta.len() > 0).unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

fn build_summary_rows(inventory: &mut EventInventory) {
    for event in &inventory.windows_events {
        if is_windows_auth_event(event) {
            inventory.auth_rows.push(AuthEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: "windows_evtx".to_string(),
                user: option_string(&event.user),
                source_ip: option_string(&event.source_ip),
                target_user: option_string(&event.target_user),
                result: option_string(&event.result),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if event.process_name.is_some() || event.command_line_summary.is_some() {
            inventory.process_rows.push(ProcessEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: "windows_evtx".to_string(),
                process_name: option_string(&event.process_name),
                process_id: option_string(&event.process_id),
                parent_process_name: option_string(&event.parent_process_name),
                command_line_summary: option_string(&event.command_line_summary),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if event.service_name.is_some() || event.action.as_deref() == Some("service_install") {
            inventory.service_rows.push(ServiceEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: "windows_evtx".to_string(),
                service_name: option_string(&event.service_name),
                action: option_string(&event.action),
                path: option_string(&event.object_path),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if event.task_name.is_some()
            || matches!(
                event.action.as_deref(),
                Some("scheduled_task_create" | "scheduled_task_update")
            )
        {
            inventory.scheduled_task_rows.push(ScheduledTaskEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: "windows_evtx".to_string(),
                task_name: option_string(&event.task_name),
                action: option_string(&event.action),
                command: option_string(&event.command_line_summary)
                    .or_else_nonempty(option_string(&event.object_path)),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if is_powershell_event(event) {
            inventory.powershell_rows.push(PowerShellEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: "windows_evtx".to_string(),
                script_summary: option_string(&event.command_line_summary)
                    .or_else_nonempty(option_string(&event.object_path)),
                user: option_string(&event.user),
                process_id: option_string(&event.process_id),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
    }

    for event in &inventory.linux_events {
        if is_linux_auth_event(event) {
            inventory.auth_rows.push(AuthEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: event
                    .source
                    .clone()
                    .unwrap_or_else(|| "linux_event".to_string()),
                user: option_string(&event.user),
                source_ip: option_string(&event.src_ip),
                target_user: String::new(),
                result: option_string(&event.result),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if event.process_name.is_some() || event.command_line_summary.is_some() {
            inventory.process_rows.push(ProcessEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: event
                    .source
                    .clone()
                    .unwrap_or_else(|| "linux_event".to_string()),
                process_name: option_string(&event.process_name),
                process_id: option_string(&event.pid),
                parent_process_name: option_string(&event.ppid),
                command_line_summary: option_string(&event.command_line_summary),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if is_linux_service_event(event) {
            inventory.service_rows.push(ServiceEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: event
                    .source
                    .clone()
                    .unwrap_or_else(|| "linux_event".to_string()),
                service_name: option_string(&event.unit),
                action: option_string(&event.action),
                path: option_string(&event.object_path),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
        if event.action.as_deref() == Some("cron") {
            inventory.scheduled_task_rows.push(ScheduledTaskEventRow {
                event_id: event.event_id.clone(),
                timestamp: option_string(&event.timestamp),
                source: event
                    .source
                    .clone()
                    .unwrap_or_else(|| "linux_event".to_string()),
                task_name: "cron".to_string(),
                action: option_string(&event.action),
                command: option_string(&event.command_line_summary),
                user: option_string(&event.user),
                raw_hash: event.raw_hash.clone(),
                parser_confidence: event.parser_confidence,
            });
        }
    }
}

fn write_event_inventory(layout: &OutputLayout, inventory: &EventInventory) -> Result<()> {
    writers::write_windows_events_jsonl(&layout.windows_events, &inventory.windows_events)?;
    writers::write_linux_events_jsonl(&layout.linux_events, &inventory.linux_events)?;
    if inventory.auth_rows.is_empty() {
        writers::write_text(
            &layout.auth_events,
            "event_id,timestamp,source,user,source_ip,target_user,result,raw_hash,parser_confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.auth_events, &inventory.auth_rows)?;
    }
    if inventory.process_rows.is_empty() {
        writers::write_text(
            &layout.process_events,
            "event_id,timestamp,source,process_name,process_id,parent_process_name,command_line_summary,user,raw_hash,parser_confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.process_events, &inventory.process_rows)?;
    }
    if inventory.service_rows.is_empty() {
        writers::write_text(
            &layout.service_events,
            "event_id,timestamp,source,service_name,action,path,user,raw_hash,parser_confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.service_events, &inventory.service_rows)?;
    }
    if inventory.scheduled_task_rows.is_empty() {
        writers::write_text(
            &layout.scheduled_task_events,
            "event_id,timestamp,source,task_name,action,command,user,raw_hash,parser_confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(
            &layout.scheduled_task_events,
            &inventory.scheduled_task_rows,
        )?;
    }
    if inventory.powershell_rows.is_empty() {
        writers::write_text(
            &layout.powershell_events,
            "event_id,timestamp,source,script_summary,user,process_id,raw_hash,parser_confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.powershell_events, &inventory.powershell_rows)?;
    }
    writers::write_parse_errors(&layout.event_parse_errors, &inventory.parse_errors)?;
    Ok(())
}

fn is_windows_auth_event(event: &WindowsEvent) -> bool {
    matches!(event.event_code.as_deref(), Some("4624" | "4625"))
        || event.source_ip.is_some()
        || event.target_user.is_some()
}

fn is_powershell_event(event: &WindowsEvent) -> bool {
    matches!(event.event_code.as_deref(), Some("4103" | "4104"))
        || event
            .provider
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("powershell")
        || event
            .channel
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("powershell")
        || event
            .process_name
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("powershell")
}

fn is_linux_auth_event(event: &LinuxEvent) -> bool {
    matches!(
        event.action.as_deref(),
        Some("login_success" | "login_failed" | "auth")
    ) || event.src_ip.is_some()
}

fn is_linux_service_event(event: &LinuxEvent) -> bool {
    matches!(
        event.action.as_deref(),
        Some("service_started" | "service_failed")
    ) || event
        .unit
        .as_deref()
        .map(|unit| unit.ends_with(".service"))
        .unwrap_or(false)
}

fn option_string(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

trait NonEmptyFallback {
    fn or_else_nonempty(self, fallback: String) -> String;
}

impl NonEmptyFallback for String {
    fn or_else_nonempty(self, fallback: String) -> String {
        if self.trim().is_empty() {
            fallback
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved_with_window(
        cutoff: Option<&str>,
        until: Option<&str>,
        full_scan: bool,
    ) -> ResolvedRun {
        ResolvedRun {
            mode: crate::model::RunMode::Analyze,
            started_at: "2026-08-27T00:00:00Z".to_string(),
            time_range: crate::model::TimeRange {
                mode: "explicit".to_string(),
                since: cutoff.map(str::to_string),
                until: until.map(str::to_string),
                hours: None,
            },
            updatetime: false,
            web_paths: Vec::new(),
            log_paths: Vec::new(),
            db_type: crate::model::DbType::Auto,
            db_log_paths: Vec::new(),
            waf_log_paths: Vec::new(),
            app_log_paths: Vec::new(),
            middleware: None,
            profile: crate::profile::ScanProfile::Quick,
            timeline: false,
            sarif: false,
            baseline: None,
            static_scan: false,
            yara_rules: Vec::new(),
            trusted_proxy: Vec::new(),
            geoip_db: None,
            ioc: Vec::new(),
            runtime_scan: false,
            runtime_target: crate::model::RuntimeTarget::Auto,
            java_home: None,
            tomcat_base: Vec::new(),
            spring_app_path: Vec::new(),
            iis_config: None,
            evtx_paths: Vec::new(),
            journal_paths: Vec::new(),
            audit_log_paths: Vec::new(),
            container_runtime: crate::model::ContainerRuntime::Auto,
            container_log_paths: Vec::new(),
            k8s_node_paths: Vec::new(),
            evidence_pack: false,
            pack_format: crate::model::PackFormat::Zip,
            component_baseline: None,
            runtime_active_check: false,
            max_event_records: 200_000,
            output_dir: std::path::PathBuf::from("/tmp/dumpall-events-window-test"),
            formats: vec![crate::model::OutputFormat::Jsonl],
            full_scan,
            max_static_file_size_mb: 10,
            max_yara_file_size_mb: 20,
            safety: crate::safety::SafetyLimits {
                max_cpu_percent: 50,
                threads: 1,
                max_file_size_mb: 512,
                max_depth: 4,
                redact: false,
                offline: true,
                verbose: false,
            },
            rules: Vec::new(),
            allowlist: None,
            memory_tool: None,
            memory_dump: false,
            memory_triage: false,
            copy_raw: false,
            xlsx_report: false,
            log_days: 30,
            event_cutoff: cutoff.map(str::to_string),
        }
    }

    #[test]
    fn window_keeps_in_range_and_drops_out_of_range() {
        let resolved =
            resolved_with_window(Some("2026-08-01T00:00:00Z"), Some("2026-08-27T00:00:00Z"), false);
        assert!(event_in_window(&resolved, Some("2026-08-15T10:00:00Z")));
        // 混合偏移：+08:00 的 08-01 08:00 等于 UTC 00:00，仍在窗口内。
        assert!(event_in_window(&resolved, Some("2026-08-01T08:00:00+08:00")));
        assert!(!event_in_window(&resolved, Some("2026-07-31T23:59:59Z")));
        assert!(!event_in_window(&resolved, Some("2026-08-27T00:00:01Z")));
    }

    #[test]
    fn window_keeps_unparseable_and_missing_timestamps() {
        let resolved = resolved_with_window(
            Some("2026-08-01T00:00:00Z"),
            Some("2026-08-27T00:00:00Z"),
            false,
        );
        assert!(event_in_window(&resolved, None));
        assert!(event_in_window(&resolved, Some("")));
        assert!(event_in_window(&resolved, Some("15/Aug/2026:08:00:00 +0000")));
    }

    #[test]
    fn full_scan_disables_until_bound() {
        let resolved = resolved_with_window(None, Some("2026-08-27T00:00:00Z"), true);
        let window = EventWindow::from_resolved(&resolved);
        assert!(!window.is_active());
        assert!(window.contains(Some("2030-01-01T00:00:00Z")));
        assert!(window.contains(None));
    }

    #[test]
    fn inactive_window_keeps_everything() {
        let resolved = resolved_with_window(None, None, false);
        assert!(!EventWindow::from_resolved(&resolved).is_active());
        assert!(event_in_window(&resolved, Some("1999-01-01T00:00:00Z")));
    }
}
