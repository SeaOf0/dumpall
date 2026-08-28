use serde::Serialize;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::display_paths;
use crate::output::paths::OutputLayout;
use crate::output::writers;
use crate::preflight::PreflightReport;

#[derive(Debug, Serialize)]
struct SystemInfo<'a> {
    hostname: &'a str,
    os: &'a str,
    arch: &'a str,
    timezone: &'a str,
    current_user: Option<&'a str>,
    privilege: &'a str,
    cpu_cores: usize,
    current_time: String,
    started_at: &'a str,
    command: &'a str,
    offline: bool,
    redact: bool,
    max_cpu_percent: u8,
    threads: usize,
    max_file_size_mb: u64,
    max_depth: usize,
    web_paths: Vec<String>,
    log_paths: Vec<String>,
}

pub fn collect(
    resolved: &ResolvedRun,
    preflight: &PreflightReport,
    layout: &OutputLayout,
) -> Result<()> {
    let info = SystemInfo {
        hostname: &preflight.hostname,
        os: &preflight.os,
        arch: &preflight.arch,
        timezone: &preflight.timezone,
        current_user: preflight.current_user.as_deref(),
        privilege: &preflight.privilege,
        cpu_cores: preflight.cpu_cores,
        current_time: crate::time_utils::now_iso(),
        started_at: &resolved.started_at,
        command: resolved.mode.as_str(),
        offline: resolved.safety.offline,
        redact: resolved.safety.redact,
        max_cpu_percent: resolved.safety.max_cpu_percent,
        threads: resolved.safety.threads,
        max_file_size_mb: resolved.safety.max_file_size_mb,
        max_depth: resolved.safety.max_depth,
        web_paths: display_paths(&resolved.web_paths),
        log_paths: display_paths(&resolved.log_paths),
    };
    writers::write_json_pretty(&layout.system_info, &info)
}
