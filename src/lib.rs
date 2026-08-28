pub mod baseline;
pub mod cli;
pub mod collector_trait;
pub mod collectors;
pub mod config;
pub mod correlation;
pub mod detectors;
pub mod discovery;
pub mod enrich;
pub mod error;
pub mod evidence_gap;
pub mod evidence_pack;
pub mod export;
pub mod file_inspect;
pub mod model;
pub mod output;
pub mod parsers;
pub mod preflight;
pub mod profile;
pub mod report;
pub mod rule_governance;
pub mod rules;
pub mod safety;
pub mod time_utils;
pub mod timeline;

use clap::Parser;
use cli::{Cli, Commands, RuleCommands};
use config::ResolvedRun;
use error::{DumpallError, Result};
use model::{Finding, RunMode, RunSummary, RunSummaryMetrics};
use output::manifest::{RunManifest, RunStats};
use output::paths::OutputLayout;
use output::writers::{self, RunLogger};

pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cli = Cli::parse_from(&args);
    run_with_cli(cli, args)
}

pub fn run_with_cli(cli: Cli, raw_args: Vec<String>) -> Result<()> {
    match cli.command {
        Commands::Scan(args) => {
            let resolved = ResolvedRun::from_common(RunMode::Scan, &args.common)?;
            if args.dry_run_plan {
                println!("{}", serde_json::to_string_pretty(&resolved.to_plan())?);
                return Ok(());
            }
            execute_minimal_run(resolved, raw_args)
        }
        Commands::Collect(args) => {
            let resolved = ResolvedRun::from_common(RunMode::Collect, &args.common)?;
            execute_minimal_run(resolved, raw_args)
        }
        Commands::Triage(args) => {
            let resolved = ResolvedRun::from_common(RunMode::Triage, &args.common)?;
            execute_minimal_run(resolved, raw_args)
        }
        Commands::Export(args) => {
            let resolved = ResolvedRun::from_common(RunMode::Export, &args.common)?;
            export::execute_export_run(resolved, args.what, raw_args)
        }
        Commands::Analyze(args) => {
            let resolved = ResolvedRun::from_common(RunMode::Analyze, &args.common)?;
            if resolved.updatetime {
                return Err(DumpallError::invalid_argument(
                    "updatetime",
                    "analyze does not access the local filesystem; use scan, collect, or triage",
                ));
            }
            if resolved.log_paths.is_empty()
                && resolved.db_log_paths.is_empty()
                && resolved.app_log_paths.is_empty()
                && resolved.waf_log_paths.is_empty()
                && !resolved.has_static_scan_scope()
                && !resolved.runtime_scan_enabled()
                && !resolved.host_events_enabled()
                && !resolved.container_enabled()
            {
                return Err(DumpallError::invalid_argument(
                    "log-path",
                    "analyze requires at least one --log-path, --db-log-path, --app-log-path, --waf-log-path, static scan scope, runtime input, host event input, or container input",
                ));
            }
            execute_minimal_run(resolved, raw_args)
        }
        Commands::Rules(args) => match args.command {
            RuleCommands::Validate(validate_args) => {
                let report = rules::validate_rule_paths(&validate_args.rules)?;
                println!("{}", report.to_human_summary());
                if report.has_errors() {
                    return Err(DumpallError::rule_validation(report.errors.join("; ")));
                }
                Ok(())
            }
        },
    }
}

fn execute_minimal_run(resolved: ResolvedRun, raw_args: Vec<String>) -> Result<()> {
    let preflight = preflight::run_preflight();
    let layout = OutputLayout::create(&resolved.output_dir)?;
    writers::initialize_required_files(&layout)?;

    let mut logger = RunLogger::create(&layout.run_log, resolved.safety.verbose)?;
    logger.log("run started")?;
    logger.log(format!("mode: {}", resolved.mode.as_str()))?;
    logger.log(format!("profile: {}", resolved.profile.as_str()))?;
    logger.log(format!("output: {}", layout.root.display()))?;
    logger.log("collection, Web log parsing, rule detection, allowlist, and scoring active")?;
    logger.log("rule package governance outputs active")?;
    rule_governance::write_rule_governance_outputs(&resolved, &layout)?;
    if resolved.database_enabled() {
        logger.log("database log discovery and parsing boundary active")?;
    }
    if resolved.waf_logs_enabled() || resolved.app_logs_enabled() {
        logger.log("WAF/CDN and application log parsing boundary active")?;
    }
    if resolved.runtime_scan_enabled() {
        logger.log(
            "runtime collector boundary active; active runtime checks remain opt-in",
        )?;
    }
    if resolved.host_events_enabled() {
        logger.log("host event collector boundary active")?;
    }
    if resolved.container_enabled() {
        logger.log("container collector boundary active; no container exec")?;
    }
    if resolved.evidence_pack_enabled() {
        logger.log("evidence-pack generation active")?;
    }

    logger.log(crate::time_utils::timezone_basis_note())?;

    // 稳定性防线：任何内部 panic 不允许让整次取证无收尾记录地终止。
    // panic 时保留已写出的中间产物，补写 PANIC_ABORT.txt 与 run.log 说明。
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_pipeline(&resolved, &preflight, &layout, &mut logger, &raw_args)
    }));
    match outcome {
        Ok(result) => result,
        Err(payload) => {
            let message = panic_message(&payload);
            let _ = logger.log(format!("run aborted by internal panic: {message}"));
            let _ = std::fs::write(
                layout.root.join("PANIC_ABORT.txt"),
                format!(
                    "dumpall aborted by an internal panic.\npanic: {message}\nstarted_at: {}\noutputs written before the abort are preserved under this directory but the run summary/manifest may be missing.\n",
                    resolved.started_at
                ),
            );
            Err(DumpallError::Message(format!(
                "internal panic aborted the run (partial outputs preserved under {}): {message}",
                layout.root.display()
            )))
        }
    }
}

/// 测试专用:进程内唯一临时目录(纳秒时间戳 + 原子序号)。
/// 只用纳秒时间戳时,并行测试在同一纳秒启动会撞目录互相删除。
#[cfg(test)]
pub(crate) fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("dumpall-{prefix}-{nanos}-{seq}"))
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn run_pipeline(
    resolved: &ResolvedRun,
    preflight: &crate::preflight::PreflightReport,
    layout: &OutputLayout,
    logger: &mut RunLogger,
    raw_args: &[String],
) -> Result<()> {
    timeline::initialize_empty_timeline(layout)?;
    if resolved.timeline_enabled() {
        logger.log("timeline: initialized v1.1 timeline outputs")?;
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut collection_errors = Vec::new();
    let mut parse_errors = Vec::new();
    let mut files_scanned = 0;
    let mut lines_parsed = 0;
    let mut rules_loaded = 0;
    let mut notes = Vec::new();
    let mut pre_detection_findings: Vec<Finding> = Vec::new();

    if resolved.mode == RunMode::Analyze {
        collectors::system::collect(resolved, preflight, layout)?;
        notes.push(
            "Analyze mode parsed only user supplied log paths; host collection was skipped."
                .to_string(),
        );
        if resolved.database_enabled() {
            let db_stats = collectors::database::collect(resolved, layout)?;
            notes.push(format!(
                "database discovery completed from analyze inputs: {} candidate(s), {} existing path(s).",
                db_stats.candidates, db_stats.existing
            ));
        }
    } else {
        let collection_report =
            collectors::run_basic_collection(resolved, preflight, layout, logger)?;
        files_scanned = collection_report.files_scanned;
        collection_errors = collection_report.errors;
        notes.extend(collection_report.notes);
    }

    if resolved.mode != RunMode::Analyze {
        if resolved.host_artifacts_enabled() {
            logger.log("collector: host artifacts (triage extension)")?;
            let artifacts_report =
                collectors::host_artifacts::collect(resolved, layout, logger)?;
            files_scanned += artifacts_report.files_scanned;
            collection_errors.extend(artifacts_report.errors);
            notes.extend(artifacts_report.notes);
        }
        if resolved.memory_dump && resolved.memory_tool.is_none() {
            logger.log("collector: native memory acquisition")?;
            let outcome = collectors::host_artifacts::native_memory_acquire(resolved, layout);
            match outcome {
                Ok(note) => notes.push(note),
                Err(error) => {
                    collection_errors.push(collectors::collection_error(
                        "memory_dump",
                        "native",
                        "acquire_native",
                        "native memory acquisition failed",
                        Some(error.to_string()),
                    ));
                }
            }
        }
        if resolved.memory_tool.is_some() {
            logger.log("collector: external memory acquisition tool")?;
            match collectors::host_artifacts::memory::run_memory_tool(resolved, layout) {
                Ok(note) => notes.push(note),
                Err(error) => {
                    collection_errors.push(collectors::collection_error(
                        "memory_tool",
                        resolved
                            .memory_tool
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_default(),
                        "run_memory_tool",
                        "external memory acquisition tool failed",
                        Some(error.to_string()),
                    ));
                }
            }
        }
        if resolved.memory_triage {
            logger.log("collector: low-impact process memory triage")?;
            match collectors::host_artifacts::process_memory_triage(resolved, layout) {
                Ok(note) => notes.push(note),
                Err(error) => collection_errors.push(collectors::collection_error(
                    "memory_triage",
                    layout.memory_triage.display().to_string(),
                    "process_memory_triage",
                    "low-impact process memory triage failed or is unsupported",
                    Some(error.to_string()),
                )),
            }
        }
        if resolved.copy_raw {
            logger.log("collector: raw evidence copy")?;
            match collectors::host_artifacts::raw_copy::copy_raw_evidence(resolved, layout) {
                Ok(note) => notes.push(note),
                Err(error) => collection_errors.push(collectors::collection_error(
                    "raw_copy",
                    layout.raw_dir.display().to_string(),
                    "copy_raw_evidence",
                    "raw evidence copy failed",
                    Some(error.to_string()),
                )),
            }
        }
        if resolved.memory_dump || resolved.memory_tool.is_some() || resolved.memory_triage {
            logger.log("collector: memory dump string scan")?;
            match collectors::host_artifacts::memstrings::scan_memory_dumps(layout) {
                Ok(hits) if hits > 0 => {
                    notes.push(format!("memory strings scan: {hits} suspicious string(s) extracted to findings/memory_strings.csv."));
                }
                Ok(_) => {}
                Err(error) => collection_errors.push(collectors::collection_error(
                    "memory_strings",
                    "raw",
                    "scan_memory_dumps",
                    "memory dump string scan failed",
                    Some(error.to_string()),
                )),
            }
        }
    }

    if resolved.mode != RunMode::Collect && resolved.static_scan_enabled() {
        logger.log("detector: built-in static file scan")?;
        let static_report =
            detectors::static_scan::run_static_scan(resolved, layout, logger)?;
        files_scanned += static_report.files_scanned;
        collection_errors.extend(static_report.errors);
        notes.push(format!(
            "static scan completed: {} file(s) inspected, {} suspicious file row(s), {} finding(s).",
            static_report.files_scanned,
            static_report.suspicious_files,
            static_report.findings.len()
        ));
        pre_detection_findings.extend(static_report.findings);
    }

    if resolved.mode != RunMode::Collect && resolved.yara_enabled() {
        logger.log("detector: optional YARA scan boundary")?;
        let yara_report = detectors::yara_scan::run_yara_scan(resolved, layout, logger)?;
        files_scanned += yara_report.files_scanned;
        collection_errors.extend(yara_report.errors);
        notes.push(format!(
            "YARA boundary completed: {} rule(s) loaded, {} file(s) inspected, {} match row(s).",
            yara_report.rules_loaded, yara_report.files_scanned, yara_report.matches
        ));
        notes.extend(yara_report.notes);
        pre_detection_findings.extend(yara_report.findings);
    }

    if resolved.runtime_scan_enabled() {
        let runtime_report = collectors::runtime::collect(resolved, layout, logger)?;
        files_scanned += runtime_report.files_scanned;
        collection_errors.extend(runtime_report.errors);
        notes.extend(runtime_report.notes);
    }

    if resolved.host_events_enabled() {
        let events_report = collectors::events::collect(resolved, layout, logger)?;
        files_scanned += events_report.files_scanned;
        lines_parsed += events_report.lines_seen;
        collection_errors.extend(events_report.errors);
        parse_errors.extend(events_report.parse_errors);
        notes.extend(events_report.notes);
    }

    if resolved.container_enabled() {
        let container_report = collectors::container::collect(resolved, layout, logger)?;
        files_scanned += container_report.files_scanned;
        lines_parsed += container_report.lines_seen;
        collection_errors.extend(container_report.errors);
        parse_errors.extend(container_report.parse_errors);
        notes.extend(container_report.notes);
    }

    if resolved.mode != RunMode::Collect {
        logger.log("parser: web access logs")?;
        let parse_report = parsers::run_log_parsing(resolved, layout, logger)?;
        let parse_error_count = parse_report.errors.len();
        lines_parsed += parse_report.lines_seen;
        parse_errors.extend(parse_report.errors);
        notes.push(format!(
            "parsing completed: {} HTTP event(s), {} line(s) inspected, {} parse error(s).",
            parse_report.events, parse_report.lines_seen, parse_error_count
        ));

        if resolved.database_enabled() {
            logger.log("parser: database logs")?;
            let db_parse_report =
                parsers::db::run_database_log_parsing(resolved, layout, logger)?;
            let db_parse_error_count = db_parse_report.errors.len();
            lines_parsed += db_parse_report.lines_seen;
            parse_errors.extend(db_parse_report.errors);
            notes.push(format!(
                "database parsing completed: {} DB event(s), {} line(s) inspected, {} parse error(s).",
                db_parse_report.events, db_parse_report.lines_seen, db_parse_error_count
            ));
        }

        if resolved.waf_logs_enabled() {
            logger.log("parser: WAF/CDN/reverse-proxy logs")?;
            let waf_parse_report =
                parsers::waf::run_waf_log_parsing(resolved, layout, logger)?;
            let waf_parse_error_count = waf_parse_report.errors.len();
            lines_parsed += waf_parse_report.lines_seen;
            parse_errors.extend(waf_parse_report.errors);
            notes.push(format!(
                "WAF/CDN parsing completed: {} WAF event(s), {} line(s) inspected, {} parse error(s).",
                waf_parse_report.events, waf_parse_report.lines_seen, waf_parse_error_count
            ));
        }

        if resolved.app_logs_enabled() {
            logger.log("parser: application framework logs")?;
            let app_parse_report =
                parsers::app::run_app_log_parsing(resolved, layout, logger)?;
            let app_parse_error_count = app_parse_report.errors.len();
            lines_parsed += app_parse_report.lines_seen;
            parse_errors.extend(app_parse_report.errors);
            notes.push(format!(
                "application log parsing completed: {} app event(s), {} line(s) inspected, {} parse error(s).",
                app_parse_report.events, app_parse_report.lines_seen, app_parse_error_count
            ));
        }

        if resolved.enrichment_enabled() {
            logger.log("enrich: offline IP, IOC, and trusted proxy context")?;
            let enrich_report = enrich::run_enrichment(resolved, layout, logger)?;
            collection_errors.extend(enrich_report.errors);
            pre_detection_findings.extend(enrich_report.findings);
            notes.push(format!(
                "enrichment completed: {} IP row(s), {} IOC match(es), {} trusted-proxy inference(s).",
                enrich_report.ip_rows, enrich_report.ioc_matches, enrich_report.proxy_inferences
            ));
        }

        logger.log("detector: rule engine")?;
        let detection_report = detectors::run_detection(resolved, layout, logger)?;
        rules_loaded = detection_report.rules_loaded;
        findings = detection_report.findings;
        findings.extend(pre_detection_findings);
        notes.push(format!(
            "detection completed: {} rule(s) loaded, {} finding(s) produced, {} finding(s) suppressed.",
            rules_loaded,
            findings.len(),
            detection_report.suppressed
        ));

        if resolved.runtime_scan_enabled() {
            logger.log("detector: runtime component inventory")?;
            let runtime_detection =
                detectors::runtime::run_runtime_detection(resolved, layout, logger)?;
            notes.push(format!(
                "runtime detection completed: {} inventory row(s), {} runtime finding(s).",
                runtime_detection.rows_seen,
                runtime_detection.findings.len()
            ));
            findings.extend(runtime_detection.findings);
        }

        if resolved.host_events_enabled() {
            logger.log("detector: host event evidence")?;
            let windows_detection = detectors::windows_events::run_windows_event_detection(
                resolved,
                layout,
                logger,
            )?;
            let linux_detection = detectors::linux_events::run_linux_event_detection(
                resolved,
                layout,
                logger,
            )?;
            notes.push(format!(
                "host event detection completed: {} Windows event row(s), {} Linux event row(s), {} host event finding(s).",
                windows_detection.rows_seen,
                linux_detection.rows_seen,
                windows_detection.findings.len() + linux_detection.findings.len()
            ));
            let mut host_event_findings = windows_detection.findings;
            host_event_findings.extend(linux_detection.findings);
            let enrichment = detectors::host_enrichment::run_host_enrichment_detection(
                resolved,
                layout,
                logger,
            )?;
            notes.push(format!(
                "host enrichment detection completed: {} scenario finding(s) (scan fan-out / ransom artifacts).",
                enrichment.findings.len()
            ));
            host_event_findings.extend(enrichment.findings);
            detectors::windows_events::write_host_events_report(
                &layout.host_events_report,
                windows_detection.rows_seen,
                linux_detection.rows_seen,
                &host_event_findings,
            )?;
            findings.extend(host_event_findings);
        }

        if resolved.container_enabled() {
            logger.log("detector: container node-side evidence")?;
            let container_detection =
                detectors::container::run_container_detection(resolved, layout, logger)?;
            notes.push(format!(
                "container detection completed: {} container row(s), {} mount row(s), {} log row(s), {} container finding(s).",
                container_detection.container_rows_seen,
                container_detection.mount_rows_seen,
                container_detection.log_rows_seen,
                container_detection.findings.len()
            ));
            findings.extend(container_detection.findings);
        }
    } else {
        notes.push("Collect mode skipped log parsing by design.".to_string());
        notes.push("Collect mode skipped detection by design.".to_string());
    }

    if resolved.copy_raw
        && (resolved.mode == RunMode::Triage
            || resolved.profile == crate::profile::ScanProfile::Triage)
    {
        logger.log("collector: finding evidence copy")?;
        match collectors::host_artifacts::evidence_copy::copy_triage_evidence(
            resolved, layout, &findings,
        ) {
            Ok(note) => notes.push(note),
            Err(error) => collection_errors.push(collectors::collection_error(
                "evidence_copy",
                layout.suspicious_evidence_dir.display().to_string(),
                "copy_triage_evidence",
                "triage finding evidence copy failed",
                Some(error.to_string()),
            )),
        }
    }

    writers::write_collection_errors(&layout.collection_errors, &collection_errors)?;
    writers::write_parse_errors(&layout.parse_errors, &parse_errors)?;

    let evidence_gaps = evidence_gap::build_evidence_gaps(resolved, &collection_errors);
    let _collection_coverage = evidence_gap::build_collection_coverage(resolved, &evidence_gaps);
    if !evidence_gaps.is_empty() {
        logger.log(format!(
            "evidence_gap: {} collection gap(s) promoted to Q5 evidence",
            evidence_gaps.len()
        ))?;
        let gap_findings = evidence_gap::findings_from_gaps(&evidence_gaps, findings.len());
        notes.push(format!(
            "evidence-gap assessment promoted {} collection gap(s) into findings/evidence_gaps.csv and low-severity Q5 findings.",
            evidence_gaps.len()
        ));
        findings.extend(gap_findings);
    } else {
        notes.push(
            "evidence-gap assessment found no collection failures that should be promoted."
                .to_string(),
        );
    }
    writers::write_evidence_gaps(&layout.evidence_gaps, &evidence_gaps)?;

    if resolved.baseline.is_some() {
        logger.log("baseline: comparing against supplied previous results")?;
        let baseline_report = baseline::apply_baseline(resolved, layout, &mut findings)?;
        notes.push(format!(
            "baseline completed: {} repeated finding(s), {} repeated file(s), {} new IP(s), {} new URL(s), {} new file(s).",
            baseline_report.repeated_findings,
            baseline_report.repeated_files,
            baseline_report.new_remote_ips,
            baseline_report.new_urls,
            baseline_report.new_files
        ));
        notes.extend(baseline_report.notes);
    }

    logger.log("correlation: evidence chains and report tables")?;
    let correlation_report = correlation::run_correlation(layout, &mut findings, logger)?;
    detectors::db::write_suspicious_db_events(layout, &findings)?;
    detectors::app::write_suspicious_app_events(layout, &findings)?;
    detectors::waf::write_suspicious_waf_events(layout, &findings)?;
    notes.push(format!(
        "correlation completed: {} relation(s), {} high-risk event(s), {} attack IP row(s), {} attack type row(s).",
        correlation_report.relation_count,
        correlation_report.high_risk_events.len(),
        correlation_report.attack_ip_stats.len(),
        correlation_report.attack_type_stats.len()
    ));
    timeline::write_attack_chains_markdown(
        &layout.attack_chains,
        &correlation_report.attack_chains,
    )?;

    if resolved.timeline_enabled() {
        logger.log("timeline: writing unified timeline and attack chains")?;
        let timeline_events =
            timeline::write_timeline_outputs(layout, &findings, &correlation_report)?;
        notes.push(format!(
            "timeline completed: {} timeline event(s), {} attack chain(s).",
            timeline_events.len(),
            correlation_report.attack_chains.len()
        ));
    }

    writers::write_findings_jsonl(&layout.findings_jsonl, &findings)?;
    writers::write_findings_csv(&layout.findings_csv, &findings)?;

    if resolved.sarif_enabled() {
        logger.log("report: writing SARIF output")?;
        report::sarif::write_sarif_report(&layout.sarif_report, &findings)?;
        notes.push(format!(
            "SARIF output written to {}.",
            layout.sarif_report.display()
        ));
    }

    let stats = RunStats {
        rules_loaded,
        files_scanned,
        lines_parsed,
        errors: (collection_errors.len() + parse_errors.len()) as u64,
    };

    let summary = RunSummary::for_run(
        env!("CARGO_PKG_VERSION"),
        resolved,
        preflight,
        layout,
        RunSummaryMetrics {
            stats: stats.clone(),
            findings_count: findings.len(),
            collection_errors: collection_errors.len(),
            parse_errors: parse_errors.len(),
            notes,
        },
    );
    report::markdown::write_summary_report(
        &layout.summary_report,
        &summary,
        &findings,
        &collection_errors,
        &evidence_gaps,
        &correlation_report,
    )?;
    report::html::write_html_report(
        &layout.html_report,
        &summary,
        &findings,
        &collection_errors,
        &evidence_gaps,
        &correlation_report,
    )?;

    let manifest = RunManifest::finished(resolved, preflight, layout, raw_args.to_vec(), stats);
    writers::write_json_pretty(&layout.manifest, &manifest)?;

    if resolved.xlsx_report {
        logger.log("report: merged xlsx workbook")?;
        match crate::output::xlsx_report::write_merged_xlsx(layout) {
            Ok(sheets) if sheets > 0 => {
                logger.log(format!(
                    "report: merged xlsx workbook written with {sheets} sheet(s) at reports/dumpall_report.xlsx"
                ))?;
            }
            Ok(_) => {}
            Err(error) => {
                logger.log(format!("report: merged xlsx workbook failed: {error}"))?;
            }
        }
    }

    if resolved.evidence_pack_enabled() {
        logger.log("evidence_pack: writing pack manifest, hashes, index, and package file")?;
        let pack = evidence_pack::generate(resolved, layout, &manifest)?;
        logger.log(format!(
            "evidence_pack: {} file(s) indexed, package {} ({})",
            pack.files_indexed,
            pack.package_path.display(),
            pack.package_sha256
        ))?;
    }

    logger.log("run finished")?;
    Ok(())
}
