use serde::{Deserialize, Serialize};

use crate::config::ResolvedRun;
use crate::model::display_paths;
use crate::output::paths::OutputLayout;
use crate::preflight::PreflightReport;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunStats {
    pub rules_loaded: usize,
    pub files_scanned: u64,
    pub lines_parsed: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub tool: String,
    pub version: String,
    pub started_at: String,
    pub finished_at: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub timezone: String,
    pub args: Vec<String>,
    pub privilege: String,
    pub current_user: Option<String>,
    pub redact: bool,
    pub offline: bool,
    pub output_dir: String,
    pub formats: Vec<String>,
    pub profile: String,
    pub timeline: bool,
    pub sarif: bool,
    pub baseline: Option<String>,
    pub evidence_pack: bool,
    pub pack_format: String,
    pub static_scan: bool,
    pub yara_enabled: bool,
    pub web_paths: Vec<String>,
    pub log_paths: Vec<String>,
    pub db_log_paths: Vec<String>,
    pub app_log_paths: Vec<String>,
    pub waf_log_paths: Vec<String>,
    pub yara_rules: Vec<String>,
    pub runtime_scan: bool,
    pub runtime_target: String,
    pub container_enabled: bool,
    pub container_runtime: String,
    pub container_log_paths: Vec<String>,
    pub k8s_node_paths: Vec<String>,
    pub java_home: Option<String>,
    pub tomcat_base: Vec<String>,
    pub spring_app_path: Vec<String>,
    pub iis_config: Option<String>,
    pub component_baseline: Option<String>,
    pub runtime_active_check: bool,
    pub memory_triage: bool,
    pub updatetime: bool,
    pub middleware: Option<String>,
    pub rules_loaded: usize,
    pub files_scanned: u64,
    pub lines_parsed: u64,
    pub errors: u64,
}

impl RunManifest {
    pub fn finished(
        resolved: &ResolvedRun,
        preflight: &PreflightReport,
        layout: &OutputLayout,
        args: Vec<String>,
        stats: RunStats,
    ) -> Self {
        Self {
            tool: "dumpall".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: resolved.started_at.clone(),
            finished_at: crate::time_utils::now_iso(),
            hostname: preflight.hostname.clone(),
            os: preflight.os.clone(),
            arch: preflight.arch.clone(),
            timezone: preflight.timezone.clone(),
            args,
            privilege: preflight.privilege.clone(),
            current_user: preflight.current_user.clone(),
            redact: resolved.safety.redact,
            offline: resolved.safety.offline,
            output_dir: layout.root.display().to_string(),
            formats: resolved
                .formats
                .iter()
                .map(|format| format.as_str().to_string())
                .collect(),
            profile: resolved.profile.as_str().to_string(),
            timeline: resolved.timeline_enabled(),
            sarif: resolved.sarif_enabled(),
            baseline: resolved
                .baseline
                .as_ref()
                .map(|path| path.display().to_string()),
            evidence_pack: resolved.evidence_pack_enabled(),
            pack_format: resolved.pack_format.as_str().to_string(),
            static_scan: resolved.static_scan_enabled(),
            yara_enabled: resolved.yara_enabled(),
            web_paths: display_paths(&resolved.web_paths),
            log_paths: display_paths(&resolved.log_paths),
            db_log_paths: display_paths(&resolved.db_log_paths),
            app_log_paths: display_paths(&resolved.app_log_paths),
            waf_log_paths: display_paths(&resolved.waf_log_paths),
            yara_rules: display_paths(&resolved.yara_rules),
            runtime_scan: resolved.runtime_scan_enabled(),
            runtime_target: resolved.runtime_target.as_str().to_string(),
            container_enabled: resolved.container_enabled(),
            container_runtime: resolved.container_runtime.as_str().to_string(),
            container_log_paths: display_paths(&resolved.container_log_paths),
            k8s_node_paths: display_paths(&resolved.k8s_node_paths),
            java_home: resolved
                .java_home
                .as_ref()
                .map(|path| path.display().to_string()),
            tomcat_base: display_paths(&resolved.tomcat_base),
            spring_app_path: display_paths(&resolved.spring_app_path),
            iis_config: resolved
                .iis_config
                .as_ref()
                .map(|path| path.display().to_string()),
            component_baseline: resolved
                .component_baseline
                .as_ref()
                .map(|path| path.display().to_string()),
            runtime_active_check: resolved.runtime_active_check,
            memory_triage: resolved.memory_triage,
            updatetime: resolved.updatetime,
            middleware: resolved
                .middleware
                .as_ref()
                .map(|middleware| middleware.as_str().to_string()),
            rules_loaded: stats.rules_loaded,
            files_scanned: stats.files_scanned,
            lines_parsed: stats.lines_parsed,
            errors: stats.errors,
        }
    }
}
