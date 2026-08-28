#[cfg(windows)]
pub(crate) mod command;

pub mod account;
pub mod container;
pub mod database;
pub mod events;
pub mod filesystem;
pub mod host_artifacts;
pub mod network;
pub mod persistence;
pub mod process;
pub mod runtime;
pub mod system;
pub mod updated_files;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers::RunLogger;
use crate::preflight::PreflightReport;

#[derive(Debug, Default)]
pub struct CollectionReport {
    pub errors: Vec<CollectionError>,
    pub files_scanned: u64,
    pub notes: Vec<String>,
}

impl CollectionReport {
    fn push_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

pub fn run_basic_collection(
    resolved: &ResolvedRun,
    preflight: &PreflightReport,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<CollectionReport> {
    let mut report = CollectionReport::default();
    logger.log("collector: system")?;
    system::collect(resolved, preflight, layout)?;

    logger.log("collector: process")?;
    process::collect(layout, &mut report.errors, resolved.safety.redact)?;

    logger.log("collector: network")?;
    network::collect(layout, &mut report.errors, resolved.safety.redact)?;

    logger.log("collector: account")?;
    account::collect(layout, &mut report.errors, resolved.safety.redact)?;

    // Account inventory is a mandatory baseline on both supported platforms.
    // Keep the deeper account-security checks here while leaving the rest of
    // the host-artifact bundle (history, hives, SUID walks, etc.) triage-only.
    #[cfg(unix)]
    {
        logger.log("collector: account security")?;
        host_artifacts::linux_ext::collect_account_security(layout, &mut report.errors)?;
    }
    #[cfg(windows)]
    {
        logger.log("collector: hidden account comparison")?;
        host_artifacts::win_ext::collect_hidden_accounts(layout, &mut report.errors)?;
    }

    logger.log("collector: persistence")?;
    persistence::collect(layout, &mut report.errors, resolved.safety.redact)?;

    logger.log("collector: filesystem")?;
    let fs_stats = filesystem::collect(resolved, layout, &mut report.errors)?;
    report.files_scanned = fs_stats.files_scanned;

    if resolved.updatetime {
        logger.log("collector: system-wide file update-time scan")?;
        let update_stats = updated_files::collect(resolved, layout, &mut report.errors)?;
        report.files_scanned += update_stats.files_scanned;
        report.push_note(format!(
            "update-time scan completed: {} file(s) inspected, {} file(s) modified within the requested window, {} tool-name hint(s).",
            update_stats.files_scanned,
            update_stats.updated_files,
            update_stats.tool_hints
        ));
    }

    if resolved.database_enabled() {
        logger.log("collector: database log discovery")?;
        let db_stats = database::collect(resolved, layout)?;
        report.push_note(format!(
            "database discovery completed: {} candidate(s), {} existing path(s).",
            db_stats.candidates, db_stats.existing
        ));
    }

    report.push_note(format!(
        "basic collectors completed: {} collection error(s), {} filesystem item(s) inspected.",
        report.errors.len(),
        report.files_scanned
    ));
    report.push_note(format!(
        "discovery completed: {} middleware candidate(s), {} web root candidate(s), {} log path candidate(s).",
        fs_stats.middleware_candidates, fs_stats.web_root_candidates, fs_stats.log_candidates
    ));
    report.push_note(
        "host collection outputs are evidence inventory and feed detection rules; they are not compromise conclusions by themselves.",
    );
    Ok(report)
}

pub(crate) fn collection_error(
    source: impl Into<String>,
    path: impl Into<String>,
    operation: impl Into<String>,
    message: impl Into<String>,
    detail: Option<String>,
) -> CollectionError {
    CollectionError {
        timestamp: crate::time_utils::now_iso(),
        source: source.into(),
        path: path.into(),
        operation: operation.into(),
        message: message.into(),
        detail,
    }
}
