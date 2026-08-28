use std::path::PathBuf;

use crate::cli::CommonArgs;
use crate::error::{DumpallError, Result};
use crate::model::{
    display_paths, ContainerRuntime, DbType, MiddlewareKind, OutputFormat, PackFormat, RunMode,
    RunPlan, RuntimeTarget, TimeRange,
};
use crate::profile::ScanProfile;
use crate::safety::SafetyLimits;
use crate::time_utils;

/// 默认分析最近 3 天；事件日志另由 --log-days 控制。
pub const DEFAULT_TIME_RANGE_HOURS: u64 = 72;

#[derive(Debug, Clone)]
pub struct ResolvedRun {
    pub mode: RunMode,
    pub started_at: String,
    pub time_range: TimeRange,
    pub updatetime: bool,
    pub web_paths: Vec<PathBuf>,
    pub log_paths: Vec<PathBuf>,
    pub db_type: DbType,
    pub db_log_paths: Vec<PathBuf>,
    pub waf_log_paths: Vec<PathBuf>,
    pub app_log_paths: Vec<PathBuf>,
    pub middleware: Option<MiddlewareKind>,
    pub profile: ScanProfile,
    pub timeline: bool,
    pub sarif: bool,
    pub baseline: Option<PathBuf>,
    pub static_scan: bool,
    pub yara_rules: Vec<PathBuf>,
    pub trusted_proxy: Vec<String>,
    pub geoip_db: Option<PathBuf>,
    pub ioc: Vec<PathBuf>,
    pub runtime_scan: bool,
    pub runtime_target: RuntimeTarget,
    pub java_home: Option<PathBuf>,
    pub tomcat_base: Vec<PathBuf>,
    pub spring_app_path: Vec<PathBuf>,
    pub iis_config: Option<PathBuf>,
    pub evtx_paths: Vec<PathBuf>,
    pub journal_paths: Vec<PathBuf>,
    pub audit_log_paths: Vec<PathBuf>,
    pub container_runtime: ContainerRuntime,
    pub container_log_paths: Vec<PathBuf>,
    pub k8s_node_paths: Vec<PathBuf>,
    pub evidence_pack: bool,
    pub pack_format: PackFormat,
    pub component_baseline: Option<PathBuf>,
    pub runtime_active_check: bool,
    pub max_event_records: u64,
    pub output_dir: PathBuf,
    pub formats: Vec<OutputFormat>,
    pub full_scan: bool,
    pub max_static_file_size_mb: u64,
    pub max_yara_file_size_mb: u64,
    pub safety: SafetyLimits,
    pub rules: Vec<PathBuf>,
    pub allowlist: Option<PathBuf>,
    pub memory_tool: Option<PathBuf>,
    pub memory_dump: bool,
    pub memory_triage: bool,
    pub copy_raw: bool,
    pub xlsx_report: bool,
    /// 事件日志采集窗口天数（--log-days，默认 30）。
    pub log_days: u64,
    /// 事件采集窗口下界（ISO）；--full-scan 时为 None（全量），
    /// 用户显式 --since 时优先于 --log-days 推算值。
    pub event_cutoff: Option<String>,
}

impl ResolvedRun {
    pub fn from_common(mode: RunMode, args: &CommonArgs) -> Result<Self> {
        if let Some(offset) = args.tz_offset.as_deref() {
            let parsed = time_utils::parse_user_offset(offset).map_err(|message| {
                DumpallError::invalid_argument("tz-offset", message)
            })?;
            time_utils::set_fixed_offset(parsed);
        }
        let file_defaults = load_file_defaults()?;
        let now = time_utils::now();
        let started_at = time_utils::format_iso(now);
        let full_scan = args.full_scan;
        let time_range = resolve_time_range(args, now, file_defaults.time_range_hours)?;
        let formats = if args.format.is_empty() {
            OutputFormat::parse_all(&file_defaults.formats)?
        } else {
            OutputFormat::parse_all(&args.format)?
        };
        let safety = SafetyLimits::from_args(args)?;
        let db_type = DbType::parse(&args.db_type)?;
        let runtime_target = RuntimeTarget::parse(&args.runtime_target)?;
        let container_runtime = ContainerRuntime::parse(&args.container_runtime)?;
        let pack_format = PackFormat::parse(&args.pack_format)?;
        let max_static_file_size_mb =
            resolve_positive_mb("max-static-file-size", args.max_static_file_size, 10)?;
        let max_yara_file_size_mb =
            resolve_positive_mb("max-yara-file-size", args.max_yara_file_size, 20)?;
        let max_event_records =
            resolve_positive_count("max-event-records", args.max_event_records, 200_000)?;
        let runtime_active_check = args.runtime_active_check && !args.no_runtime_active_check;
        let middleware = args
            .middleware
            .as_deref()
            .map(MiddlewareKind::parse)
            .transpose()?;
        let output_dir = args.output.clone().unwrap_or_else(|| {
            PathBuf::from(format!("results_{}", time_utils::format_result_stamp(now)))
        });

        let profile = if mode == RunMode::Triage && args.profile == ScanProfile::Quick {
            ScanProfile::Triage
        } else {
            args.profile
        };
        let (default_evtx, default_journal, default_audit) = default_host_event_paths(profile);
        let evtx_paths = if args.evtx_path.is_empty() {
            default_evtx
        } else {
            args.evtx_path.clone()
        };
        let journal_paths = if args.journal_path.is_empty() {
            default_journal
        } else {
            args.journal_path.clone()
        };
        let audit_log_paths = if args.audit_log_path.is_empty() {
            default_audit
        } else {
            args.audit_log_path.clone()
        };
        let copy_raw = (args.copy_raw || mode == RunMode::Triage) && !args.no_copy_raw;
        let memory_dump = args.memory_dump;
        let xlsx_report = (args.xlsx_report || mode == RunMode::Triage) && !args.no_xlsx_report;
        // 事件采集窗口：默认 30 天；用户显式 --since 优先；--full-scan 全量。0 非法。
        let log_days = args.log_days.unwrap_or(30);
        if log_days == 0 {
            return Err(DumpallError::invalid_argument(
                "log-days",
                "must be greater than zero; use --full-scan for unbounded collection",
            ));
        }
        let event_cutoff = if full_scan {
            None
        } else if args.since.is_some() {
            time_range.since.clone()
        } else {
            // 无显式 --since 时以 --until(未指定时为当前时间)为锚向前推 log_days:
            // 显式回溯 --until 时事件窗口与分析窗口保持同一起点,
            // 而不是一边锚定 until、一边锚定真实 now 的不对称区间。
            let anchor = time_range
                .until
                .as_deref()
                .and_then(|value| time_utils::parse_datetime(value).ok())
                .unwrap_or(now);
            Some(time_utils::format_iso(
                anchor - time::Duration::days(log_days as i64),
            ))
        };

        Ok(Self {
            mode,
            started_at,
            time_range,
            updatetime: args.updatetime,
            web_paths: args.web_path.clone(),
            log_paths: args.log_path.clone(),
            db_type,
            db_log_paths: args.db_log_path.clone(),
            waf_log_paths: args.waf_log_path.clone(),
            app_log_paths: args.app_log_path.clone(),
            middleware,
            profile,
            timeline: args.timeline,
            sarif: args.sarif,
            baseline: args.baseline.clone(),
            static_scan: args.static_scan,
            yara_rules: args.yara_rules.clone(),
            trusted_proxy: args.trusted_proxy.clone(),
            geoip_db: args.geoip_db.clone(),
            ioc: args.ioc.clone(),
            runtime_scan: args.runtime_scan,
            runtime_target,
            java_home: args.java_home.clone(),
            tomcat_base: args.tomcat_base.clone(),
            spring_app_path: args.spring_app_path.clone(),
            iis_config: args.iis_config.clone(),
            evtx_paths,
            journal_paths,
            audit_log_paths,
            container_runtime,
            container_log_paths: args.container_log_path.clone(),
            k8s_node_paths: args.k8s_node_path.clone(),
            evidence_pack: args.evidence_pack,
            pack_format,
            component_baseline: args.component_baseline.clone(),
            runtime_active_check,
            max_event_records,
            output_dir,
            formats,
            full_scan,
            max_static_file_size_mb,
            max_yara_file_size_mb,
            safety,
            rules: args.rules.clone(),
            allowlist: args.allowlist.clone(),
            memory_tool: args.memory_tool.clone(),
            memory_dump,
            memory_triage: args.memory_triage,
            copy_raw,
            xlsx_report,
            log_days,
            event_cutoff,
        })
    }

    pub fn to_plan(&self) -> RunPlan {
        RunPlan {
            command: self.mode.as_str().to_string(),
            dry_run: true,
            time_range: self.time_range.clone(),
            updatetime: self.updatetime,
            web_paths: display_paths(&self.web_paths),
            log_paths: display_paths(&self.log_paths),
            db_type: self.db_type.as_str().to_string(),
            db_log_paths: display_paths(&self.db_log_paths),
            waf_log_paths: display_paths(&self.waf_log_paths),
            app_log_paths: display_paths(&self.app_log_paths),
            middleware: self
                .middleware
                .as_ref()
                .map(|middleware| middleware.as_str().to_string()),
            output_dir: self.output_dir.display().to_string(),
            formats: self
                .formats
                .iter()
                .map(|format| format.as_str().to_string())
                .collect(),
            full_scan: self.full_scan,
            profile: self.profile.as_str().to_string(),
            timeline: self.timeline_enabled(),
            sarif: self.sarif_enabled(),
            baseline: self
                .baseline
                .as_ref()
                .map(|path| path.display().to_string()),
            static_scan: self.static_scan_enabled(),
            yara_rules: display_paths(&self.yara_rules),
            trusted_proxy: self.trusted_proxy.clone(),
            geoip_db: self
                .geoip_db
                .as_ref()
                .map(|path| path.display().to_string()),
            ioc: display_paths(&self.ioc),
            runtime_scan: self.runtime_scan_enabled(),
            runtime_target: self.runtime_target.as_str().to_string(),
            java_home: self
                .java_home
                .as_ref()
                .map(|path| path.display().to_string()),
            tomcat_base: display_paths(&self.tomcat_base),
            spring_app_path: display_paths(&self.spring_app_path),
            iis_config: self
                .iis_config
                .as_ref()
                .map(|path| path.display().to_string()),
            evtx_path: display_paths(&self.evtx_paths),
            journal_path: display_paths(&self.journal_paths),
            audit_log_path: display_paths(&self.audit_log_paths),
            container_enabled: self.container_enabled(),
            container_runtime: self.container_runtime.as_str().to_string(),
            container_log_path: display_paths(&self.container_log_paths),
            k8s_node_path: display_paths(&self.k8s_node_paths),
            evidence_pack: self.evidence_pack_enabled(),
            pack_format: self.pack_format.as_str().to_string(),
            component_baseline: self
                .component_baseline
                .as_ref()
                .map(|path| path.display().to_string()),
            runtime_active_check: self.runtime_active_check,
            memory_triage: self.memory_triage,
            max_event_records: self.max_event_records,
            collector_plans: crate::collector_trait::dry_run_plan(self),
            max_cpu_percent: self.safety.max_cpu_percent,
            threads: self.safety.threads,
            max_file_size_mb: self.safety.max_file_size_mb,
            max_static_file_size_mb: self.max_static_file_size_mb,
            max_yara_file_size_mb: self.max_yara_file_size_mb,
            max_depth: self.safety.max_depth,
            redact: self.safety.redact,
            offline: self.safety.offline,
            rules: display_paths(&self.rules),
            allowlist: self
                .allowlist
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }

    pub fn timeline_enabled(&self) -> bool {
        self.timeline
            || self.profile.capabilities().timeline
            || self.runtime_scan_enabled()
            || self.host_events_enabled()
            || self.container_enabled()
    }

    pub fn sarif_enabled(&self) -> bool {
        self.sarif || self.profile.capabilities().sarif
    }

    pub fn static_scan_enabled(&self) -> bool {
        self.static_scan || self.profile.capabilities().static_scan
    }

    pub fn yara_enabled(&self) -> bool {
        !self.yara_rules.is_empty()
    }

    pub fn has_static_scan_scope(&self) -> bool {
        self.static_scan_enabled() || self.yara_enabled()
    }

    pub fn database_enabled(&self) -> bool {
        self.profile.capabilities().database_logs
            || !self.db_log_paths.is_empty()
            || !self.db_type.is_auto()
    }

    pub fn waf_logs_enabled(&self) -> bool {
        self.profile.capabilities().waf_logs || !self.waf_log_paths.is_empty()
    }

    pub fn app_logs_enabled(&self) -> bool {
        self.profile.capabilities().app_logs || !self.app_log_paths.is_empty()
    }

    pub fn enrichment_enabled(&self) -> bool {
        self.profile.capabilities().enrichment
            || !self.trusted_proxy.is_empty()
            || self.geoip_db.is_some()
            || !self.ioc.is_empty()
    }

    pub fn runtime_scan_enabled(&self) -> bool {
        self.runtime_scan
            || self.profile.capabilities().runtime_scan
            || self.runtime_target != RuntimeTarget::Auto
            || self.java_home.is_some()
            || !self.tomcat_base.is_empty()
            || !self.spring_app_path.is_empty()
            || self.iis_config.is_some()
            || self.component_baseline.is_some()
    }

    pub fn host_events_enabled(&self) -> bool {
        self.profile.capabilities().host_events
            || !self.evtx_paths.is_empty()
            || !self.journal_paths.is_empty()
            || !self.audit_log_paths.is_empty()
    }

    pub fn container_enabled(&self) -> bool {
        self.profile.capabilities().container
            || self.container_runtime != ContainerRuntime::Auto
            || !self.container_log_paths.is_empty()
            || !self.k8s_node_paths.is_empty()
    }

    pub fn evidence_pack_enabled(&self) -> bool {
        self.evidence_pack || self.profile.capabilities().evidence_pack
    }

    pub fn host_artifacts_enabled(&self) -> bool {
        self.profile.capabilities().host_artifacts || self.mode == RunMode::Triage
    }
}

/// 当 profile 开启主机事件能力且用户未显式指定事件源时，返回平台默认的事件日志路径。
/// 只返回当前存在的路径，避免在无关平台上产生噪声。
pub(crate) fn default_host_event_paths(
    profile: ScanProfile,
) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
    let mut evtx = Vec::new();
    let mut journal = Vec::new();
    let mut audit = Vec::new();
    if !profile.capabilities().host_events {
        return (evtx, journal, audit);
    }
    if cfg!(windows) {
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            let logs = PathBuf::from(system_root)
                .join("System32")
                .join("winevt")
                .join("Logs");
            // 直接纳入整个 winevt\Logs 目录：collector 会遍历全部 .evtx 通道，
            // 覆盖"Windows 日志"（Application/Security/Setup/System/ForwardedEvents）
            // 与"应用程序和服务日志"整棵树（PowerShell/Sysmon/TaskScheduler/WMI/
            // RDP/Defender/IIS/DNS-Server/Firewall 等全部），
            // 由 --max-file-size 与 --max-event-records 兜底。
            if logs.exists() {
                evtx.push(logs);
            }
        }
    } else {
        for candidate in [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/audit",
            "/var/log/audit/audit.log",
        ] {
            let path = PathBuf::from(candidate);
            if path.exists() {
                audit.push(path);
            }
        }
        let _ = &mut journal;
    }
    (evtx, journal, audit)
}

fn resolve_positive_mb(field: &'static str, value: Option<u64>, default_value: u64) -> Result<u64> {
    let resolved = value.unwrap_or(default_value);
    if resolved == 0 {
        return Err(DumpallError::invalid_argument(
            field,
            "value must be greater than zero",
        ));
    }
    Ok(resolved)
}

fn resolve_positive_count(
    field: &'static str,
    value: Option<u64>,
    default_value: u64,
) -> Result<u64> {
    let resolved = value.unwrap_or(default_value);
    if resolved == 0 {
        return Err(DumpallError::invalid_argument(
            field,
            "value must be greater than zero",
        ));
    }
    Ok(resolved)
}

/// 可选的 config/default.toml 默认值（仅作为 CLI 未显式指定时的默认值来源；
/// 解析失败按非法参数报错，避免用户编辑后静默不生效）。
#[derive(Debug, Default, serde::Deserialize)]
struct FileDefaults {
    time_range_hours: Option<u64>,
    #[serde(default)]
    formats: Vec<String>,
}

fn load_file_defaults() -> Result<FileDefaults> {
    let path = std::path::Path::new("config").join("default.toml");
    if !path.exists() {
        return Ok(FileDefaults::default());
    }
    let text = std::fs::read_to_string(&path)?;
    toml::from_str(&text).map_err(|error| {
        DumpallError::invalid_argument(
            "config/default.toml",
            format!("could not parse file defaults: {error}"),
        )
    })
}

fn resolve_time_range(
    args: &CommonArgs,
    now: time::OffsetDateTime,
    file_default_hours: Option<u64>,
) -> Result<TimeRange> {
    if args.full_scan {
        return Ok(TimeRange {
            mode: "full_scan".to_string(),
            since: None,
            until: None,
            hours: None,
        });
    }

    let until = match args.until.as_deref() {
        Some(value) => time_utils::parse_datetime(value).map_err(|message| {
            DumpallError::invalid_argument("until", format!("could not parse datetime: {message}"))
        })?,
        None => now,
    };

    if let Some(since) = args.since.as_deref() {
        let since = time_utils::parse_datetime(since).map_err(|message| {
            DumpallError::invalid_argument("since", format!("could not parse datetime: {message}"))
        })?;
        if since > until {
            return Err(DumpallError::invalid_argument(
                "since",
                "since must not be later than until (empty time window)",
            ));
        }
        return Ok(TimeRange {
            mode: "explicit".to_string(),
            since: Some(time_utils::format_iso(since)),
            until: Some(time_utils::format_iso(until)),
            hours: None,
        });
    }

    let hours = args.time_range.or(file_default_hours).unwrap_or(DEFAULT_TIME_RANGE_HOURS);
    if hours == 0 {
        return Err(DumpallError::invalid_argument(
            "time-range",
            "time range must be greater than zero",
        ));
    }

    let since = until - time::Duration::hours(hours as i64);
    Ok(TimeRange {
        mode: "recent_hours".to_string(),
        since: Some(time_utils::format_iso(since)),
        until: Some(time_utils::format_iso(until)),
        hours: Some(hours),
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn scan_defaults_match_v1_contract() {
        let cli = Cli::parse_from(["dumpall", "scan"]);
        let Commands::Scan(scan) = cli.command else {
            panic!("expected scan command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &scan.common).unwrap();

        assert_eq!(resolved.time_range.hours, Some(72));
        assert!(!resolved.updatetime);
        assert_eq!(resolved.profile, ScanProfile::Quick);
        assert!(!resolved.timeline_enabled());
        assert!(!resolved.sarif_enabled());
        assert!(resolved.baseline.is_none());
        assert!(!resolved.database_enabled());
        assert!(!resolved.waf_logs_enabled());
        assert!(!resolved.app_logs_enabled());
        assert!(!resolved.static_scan_enabled());
        assert!(!resolved.yara_enabled());
        assert!(!resolved.enrichment_enabled());
        assert!(resolved.safety.offline);
        assert_eq!(resolved.safety.max_cpu_percent, 50);
        assert_eq!(resolved.safety.max_file_size_mb, 512);
        assert_eq!(resolved.max_static_file_size_mb, 10);
        assert_eq!(resolved.max_yara_file_size_mb, 20);
        assert_eq!(resolved.safety.max_depth, 8);
        assert_eq!(
            resolved.formats,
            vec![
                OutputFormat::Jsonl,
                OutputFormat::Csv,
                OutputFormat::Markdown,
                OutputFormat::Html
            ]
        );
    }

    #[test]
    fn triage_does_not_enable_memory_without_explicit_flag() {
        let cli = Cli::parse_from(["dumpall", "triage"]);
        let Commands::Triage(triage) = cli.command else {
            panic!("expected triage command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Triage, &triage.common).unwrap();

        assert_eq!(resolved.profile, ScanProfile::Triage);
        assert!(!resolved.memory_dump);
        assert!(resolved.memory_tool.is_none());
        assert!(!resolved.memory_triage);
        assert!(resolved.copy_raw);
        assert!(resolved.evidence_pack_enabled());
    }

    #[test]
    fn updatetime_flag_is_preserved_in_plan() {
        let cli = Cli::parse_from(["dumpall", "scan", "--updatetime", "--time-range", "6"]);
        let Commands::Scan(scan) = cli.command else {
            panic!("expected scan command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &scan.common).unwrap();

        assert!(resolved.updatetime);
        assert_eq!(resolved.time_range.hours, Some(6));
        assert!(resolved.to_plan().updatetime);
    }

    #[test]
    fn explicit_since_overrides_recent_window() {
        let cli = Cli::parse_from([
            "dumpall",
            "scan",
            "--time-range",
            "12",
            "--since",
            "2026-05-15T00:00:00Z",
            "--until",
            "2026-05-15T01:00:00Z",
            "--output",
            "results_fixed",
        ]);
        let Commands::Scan(scan) = cli.command else {
            panic!("expected scan command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &scan.common).unwrap();

        assert_eq!(resolved.time_range.mode, "explicit");
        assert_eq!(resolved.time_range.hours, None);
        assert_eq!(
            resolved.time_range.since.as_deref(),
            Some("2026-05-15T00:00:00Z")
        );
    }

    #[test]
    fn full_ir_profile_enables_timeline_boundary() {
        let cli = Cli::parse_from(["dumpall", "scan", "--profile", "full-ir"]);
        let Commands::Scan(scan) = cli.command else {
            panic!("expected scan command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Scan, &scan.common).unwrap();

        assert_eq!(resolved.profile, ScanProfile::FullIr);
        assert!(resolved.timeline_enabled());
        assert!(resolved.database_enabled());
        assert!(resolved.static_scan_enabled());
    }

    #[test]
    fn explicit_db_log_path_enables_database_boundary() {
        let cli = Cli::parse_from(["dumpall", "analyze", "--db-log-path", "mysql.log"]);
        let Commands::Analyze(analyze) = cli.command else {
            panic!("expected analyze command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &analyze.common).unwrap();

        assert_eq!(resolved.db_type, DbType::Auto);
        assert!(resolved.database_enabled());
    }

    #[test]
    fn explicit_static_and_yara_inputs_enable_m3_boundaries() {
        let cli = Cli::parse_from([
            "dumpall",
            "analyze",
            "--web-path",
            "www",
            "--static-scan",
            "--yara-rules",
            "rules/webshell.yar",
        ]);
        let Commands::Analyze(analyze) = cli.command else {
            panic!("expected analyze command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &analyze.common).unwrap();

        assert!(resolved.static_scan_enabled());
        assert!(resolved.yara_enabled());
        assert!(resolved.has_static_scan_scope());
    }

    #[test]
    fn explicit_enrichment_inputs_enable_m4_boundary() {
        let cli = Cli::parse_from([
            "dumpall",
            "analyze",
            "--log-path",
            "access.log",
            "--trusted-proxy",
            "10.0.0.0/8",
            "--ioc",
            "ioc.csv",
        ]);
        let Commands::Analyze(analyze) = cli.command else {
            panic!("expected analyze command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &analyze.common).unwrap();

        assert!(resolved.enrichment_enabled());
        assert_eq!(resolved.trusted_proxy, vec!["10.0.0.0/8"]);
        assert_eq!(resolved.ioc.len(), 1);
    }

    #[test]
    fn explicit_app_and_waf_inputs_enable_m5_boundaries() {
        let cli = Cli::parse_from([
            "dumpall",
            "analyze",
            "--app-log-path",
            "application.log",
            "--waf-log-path",
            "waf.jsonl",
        ]);
        let Commands::Analyze(analyze) = cli.command else {
            panic!("expected analyze command");
        };
        let resolved = ResolvedRun::from_common(RunMode::Analyze, &analyze.common).unwrap();

        assert!(resolved.app_logs_enabled());
        assert!(resolved.waf_logs_enabled());
        assert_eq!(resolved.app_log_paths.len(), 1);
        assert_eq!(resolved.waf_log_paths.len(), 1);
    }
}
