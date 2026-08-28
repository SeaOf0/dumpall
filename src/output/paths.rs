use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{DumpallError, Result};

#[derive(Debug, Clone)]
pub struct OutputLayout {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub run_log: PathBuf,
    pub collection_dir: PathBuf,
    pub parsed_dir: PathBuf,
    pub enrich_dir: PathBuf,
    pub ip_enrichment: PathBuf,
    pub geoip_summary: PathBuf,
    pub asn_summary: PathBuf,
    pub ioc_sources: PathBuf,
    pub timeline_dir: PathBuf,
    pub timeline_jsonl: PathBuf,
    pub timeline_csv: PathBuf,
    pub attack_chains: PathBuf,
    pub rules_used_dir: PathBuf,
    pub rules_manifest: PathBuf,
    pub effective_allowlist: PathBuf,
    pub runtime_dir: PathBuf,
    pub java_components: PathBuf,
    pub tomcat_components: PathBuf,
    pub spring_mappings: PathBuf,
    pub iis_modules: PathBuf,
    pub aspnet_handlers: PathBuf,
    pub runtime_warnings: PathBuf,
    pub component_diff: PathBuf,
    pub events_dir: PathBuf,
    pub windows_events: PathBuf,
    pub linux_events: PathBuf,
    pub auth_events: PathBuf,
    pub process_events: PathBuf,
    pub service_events: PathBuf,
    pub scheduled_task_events: PathBuf,
    pub powershell_events: PathBuf,
    pub event_parse_errors: PathBuf,
    pub containers_dir: PathBuf,
    pub containers: PathBuf,
    pub images: PathBuf,
    pub mounts: PathBuf,
    pub container_network: PathBuf,
    pub container_logs: PathBuf,
    pub container_findings: PathBuf,
    pub evidence_pack_dir: PathBuf,
    pub pack_manifest: PathBuf,
    pub pack_hashes: PathBuf,
    pub evidence_index_csv: PathBuf,
    pub evidence_index_json: PathBuf,
    pub review_guide: PathBuf,
    pub system_info: PathBuf,
    pub middleware: PathBuf,
    pub processes: PathBuf,
    pub process_tree: PathBuf,
    pub network_connections: PathBuf,
    pub users: PathBuf,
    pub privileged_users: PathBuf,
    pub logons: PathBuf,
    pub scheduled_tasks: PathBuf,
    pub startup_items: PathBuf,
    pub services: PathBuf,
    pub web_roots: PathBuf,
    pub discovered_logs: PathBuf,
    pub discovered_db_logs: PathBuf,
    pub discovered_app_logs: PathBuf,
    pub discovered_waf_logs: PathBuf,
    pub http_events: PathBuf,
    pub db_events: PathBuf,
    pub app_events: PathBuf,
    pub waf_events: PathBuf,
    pub collection_errors: PathBuf,
    pub parse_errors: PathBuf,
    pub findings_dir: PathBuf,
    pub findings_jsonl: PathBuf,
    pub findings_csv: PathBuf,
    pub high_risk_events: PathBuf,
    pub attack_ip_stats: PathBuf,
    pub attack_type_stats: PathBuf,
    pub recent_web_files: PathBuf,
    pub suspicious_files: PathBuf,
    pub suspicious_processes: PathBuf,
    pub suspicious_network: PathBuf,
    pub suspicious_db_events: PathBuf,
    pub suspicious_app_events: PathBuf,
    pub suspicious_waf_events: PathBuf,
    pub evidence_gaps: PathBuf,
    pub updated_files: PathBuf,
    pub yara_matches: PathBuf,
    pub ioc_matches: PathBuf,
    pub evidence_dir: PathBuf,
    pub file_hashes: PathBuf,
    pub suspicious_evidence_dir: PathBuf,
    pub evidence_copy_manifest: PathBuf,
    pub reports_dir: PathBuf,
    pub html_report: PathBuf,
    pub summary_report: PathBuf,
    pub runtime_report: PathBuf,
    pub host_events_report: PathBuf,
    pub container_report: PathBuf,
    pub sarif_report: PathBuf,
    pub shell_history: PathBuf,
    pub ssh_keys: PathBuf,
    pub sshd_config_flags: PathBuf,
    pub sudoers: PathBuf,
    pub login_history: PathBuf,
    pub kernel_modules: PathBuf,
    pub arp_cache: PathBuf,
    pub unix_sockets: PathBuf,
    pub dns_config: PathBuf,
    pub dns_cache: PathBuf,
    pub process_env: PathBuf,
    pub persistence_misc: PathBuf,
    pub registry_persistence: PathBuf,
    pub wmi_subscriptions: PathBuf,
    pub drivers: PathBuf,
    pub firewall_rules: PathBuf,
    pub shares: PathBuf,
    pub suid_files: PathBuf,
    pub temp_files: PathBuf,
    pub fs_anomalies: PathBuf,
    pub bin_dir_changes: PathBuf,
    pub installed_packages: PathBuf,
    pub deleted_open_files: PathBuf,
    pub raw_dir: PathBuf,
    pub raw_manifest: PathBuf,
    pub kernel_params: PathBuf,
    pub account_security: PathBuf,
    pub rc_files: PathBuf,
    pub file_capabilities: PathBuf,
    pub package_integrity: PathBuf,
    pub hidden_processes: PathBuf,
    pub recycle_bin: PathBuf,
    pub lnk_inventory: PathBuf,
    pub appcompat_sdb: PathBuf,
    pub user_dirs: PathBuf,
    pub memory_strings: PathBuf,
    pub memory_triage: PathBuf,
}

impl OutputLayout {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.exists() {
            return Err(DumpallError::OutputDirectoryExists(root));
        }

        let layout = Self::from_root(root);
        for directory in [
            &layout.root,
            &layout.collection_dir,
            &layout.parsed_dir,
            &layout.enrich_dir,
            &layout.timeline_dir,
            &layout.rules_used_dir,
            &layout.runtime_dir,
            &layout.events_dir,
            &layout.containers_dir,
            &layout.evidence_pack_dir,
            &layout.findings_dir,
            &layout.evidence_dir,
            &layout.suspicious_evidence_dir,
            &layout.reports_dir,
            &layout.raw_dir,
        ] {
            fs::create_dir_all(directory)?;
            restrict_directory_permissions(directory)?;
        }
        Ok(layout)
    }

    pub fn from_root(root: PathBuf) -> Self {
        let collection_dir = root.join("collection");
        let parsed_dir = root.join("parsed");
        let enrich_dir = root.join("enrich");
        let timeline_dir = root.join("timeline");
        let rules_used_dir = root.join("rules_used");
        let runtime_dir = root.join("runtime");
        let events_dir = root.join("events");
        let containers_dir = root.join("containers");
        let evidence_pack_dir = root.join("evidence_pack");
        let findings_dir = root.join("findings");
        let evidence_dir = root.join("evidence");
        let reports_dir = root.join("reports");
        let raw_dir = root.join("raw");

        Self {
            manifest: root.join("manifest.json"),
            run_log: root.join("run.log"),
            system_info: collection_dir.join("system_info.json"),
            middleware: collection_dir.join("middleware.csv"),
            processes: collection_dir.join("processes.csv"),
            process_tree: collection_dir.join("process_tree.txt"),
            network_connections: collection_dir.join("network_connections.csv"),
            users: collection_dir.join("users.csv"),
            privileged_users: collection_dir.join("privileged_users.csv"),
            logons: collection_dir.join("logons.csv"),
            scheduled_tasks: collection_dir.join("scheduled_tasks.csv"),
            startup_items: collection_dir.join("startup_items.csv"),
            services: collection_dir.join("services.csv"),
            web_roots: collection_dir.join("web_roots.csv"),
            discovered_logs: collection_dir.join("discovered_logs.csv"),
            discovered_db_logs: collection_dir.join("discovered_db_logs.csv"),
            discovered_app_logs: collection_dir.join("discovered_app_logs.csv"),
            discovered_waf_logs: collection_dir.join("discovered_waf_logs.csv"),
            http_events: collection_dir.join("http_events.jsonl"),
            db_events: parsed_dir.join("db_events.jsonl"),
            app_events: parsed_dir.join("app_events.jsonl"),
            waf_events: parsed_dir.join("waf_events.jsonl"),
            ip_enrichment: enrich_dir.join("ip_enrichment.csv"),
            geoip_summary: enrich_dir.join("geoip_summary.csv"),
            asn_summary: enrich_dir.join("asn_summary.csv"),
            ioc_sources: enrich_dir.join("ioc_sources.json"),
            rules_manifest: rules_used_dir.join("rules_manifest.json"),
            effective_allowlist: rules_used_dir.join("effective_allowlist.toml"),
            java_components: runtime_dir.join("java_components.csv"),
            tomcat_components: runtime_dir.join("tomcat_components.csv"),
            spring_mappings: runtime_dir.join("spring_mappings.csv"),
            iis_modules: runtime_dir.join("iis_modules.csv"),
            aspnet_handlers: runtime_dir.join("aspnet_handlers.csv"),
            runtime_warnings: runtime_dir.join("runtime_warnings.csv"),
            component_diff: runtime_dir.join("component_diff.csv"),
            windows_events: events_dir.join("windows_events.jsonl"),
            linux_events: events_dir.join("linux_events.jsonl"),
            auth_events: events_dir.join("auth_events.csv"),
            process_events: events_dir.join("process_events.csv"),
            service_events: events_dir.join("service_events.csv"),
            scheduled_task_events: events_dir.join("scheduled_task_events.csv"),
            powershell_events: events_dir.join("powershell_events.csv"),
            event_parse_errors: events_dir.join("event_parse_errors.csv"),
            containers: containers_dir.join("containers.csv"),
            images: containers_dir.join("images.csv"),
            mounts: containers_dir.join("mounts.csv"),
            container_network: containers_dir.join("container_network.csv"),
            container_logs: containers_dir.join("container_logs.jsonl"),
            container_findings: containers_dir.join("container_findings.csv"),
            pack_manifest: evidence_pack_dir.join("pack_manifest.json"),
            pack_hashes: evidence_pack_dir.join("pack_hashes.csv"),
            evidence_index_csv: evidence_pack_dir.join("evidence_index.csv"),
            evidence_index_json: evidence_pack_dir.join("evidence_index.json"),
            review_guide: evidence_pack_dir.join("review_guide.md"),
            collection_errors: collection_dir.join("collection_errors.csv"),
            parse_errors: collection_dir.join("parse_errors.csv"),
            findings_jsonl: findings_dir.join("findings.jsonl"),
            findings_csv: findings_dir.join("findings.csv"),
            high_risk_events: findings_dir.join("high_risk_events.csv"),
            attack_ip_stats: findings_dir.join("attack_ip_stats.csv"),
            attack_type_stats: findings_dir.join("attack_type_stats.csv"),
            recent_web_files: findings_dir.join("recent_web_files.csv"),
            suspicious_files: findings_dir.join("suspicious_files.csv"),
            suspicious_processes: findings_dir.join("suspicious_processes.csv"),
            suspicious_network: findings_dir.join("suspicious_network.csv"),
            suspicious_db_events: findings_dir.join("suspicious_db_events.csv"),
            suspicious_app_events: findings_dir.join("suspicious_app_events.csv"),
            suspicious_waf_events: findings_dir.join("suspicious_waf_events.csv"),
            evidence_gaps: findings_dir.join("evidence_gaps.csv"),
            updated_files: findings_dir.join("updated_files.csv"),
            yara_matches: findings_dir.join("yara_matches.csv"),
            ioc_matches: findings_dir.join("ioc_matches.csv"),
            file_hashes: evidence_dir.join("file_hashes.csv"),
            suspicious_evidence_dir: evidence_dir.join("suspicious_files"),
            evidence_copy_manifest: evidence_dir.join("evidence_copy_manifest.csv"),
            html_report: reports_dir.join("report.html"),
            summary_report: reports_dir.join("summary_report.md"),
            runtime_report: reports_dir.join("runtime_report.md"),
            host_events_report: reports_dir.join("host_events_report.md"),
            container_report: reports_dir.join("container_report.md"),
            sarif_report: reports_dir.join("dumpall.sarif"),
            shell_history: collection_dir.join("shell_history.csv"),
            ssh_keys: collection_dir.join("ssh_keys.csv"),
            sshd_config_flags: collection_dir.join("sshd_config_flags.csv"),
            sudoers: collection_dir.join("sudoers.csv"),
            login_history: collection_dir.join("login_history.csv"),
            kernel_modules: collection_dir.join("kernel_modules.csv"),
            arp_cache: collection_dir.join("arp_cache.csv"),
            unix_sockets: collection_dir.join("unix_sockets.csv"),
            dns_config: collection_dir.join("dns_config.csv"),
            dns_cache: collection_dir.join("dns_cache.csv"),
            process_env: collection_dir.join("process_env.csv"),
            persistence_misc: collection_dir.join("persistence_misc.csv"),
            registry_persistence: collection_dir.join("registry_persistence.csv"),
            wmi_subscriptions: collection_dir.join("wmi_subscriptions.csv"),
            drivers: collection_dir.join("drivers.csv"),
            firewall_rules: collection_dir.join("firewall_rules.csv"),
            shares: collection_dir.join("shares.csv"),
            suid_files: collection_dir.join("suid_files.csv"),
            temp_files: collection_dir.join("temp_files.csv"),
            fs_anomalies: collection_dir.join("fs_anomalies.csv"),
            bin_dir_changes: collection_dir.join("bin_dir_changes.csv"),
            installed_packages: collection_dir.join("installed_packages.csv"),
            deleted_open_files: findings_dir.join("deleted_open_files.csv"),
            raw_manifest: raw_dir.join("raw_manifest.csv"),
            kernel_params: collection_dir.join("kernel_params.csv"),
            account_security: collection_dir.join("account_security.csv"),
            rc_files: collection_dir.join("rc_files.csv"),
            file_capabilities: collection_dir.join("file_capabilities.csv"),
            package_integrity: findings_dir.join("package_integrity.csv"),
            hidden_processes: findings_dir.join("hidden_processes.csv"),
            recycle_bin: collection_dir.join("recycle_bin.csv"),
            lnk_inventory: collection_dir.join("lnk_inventory.csv"),
            appcompat_sdb: collection_dir.join("appcompat_sdb.csv"),
            user_dirs: collection_dir.join("user_dirs.csv"),
            memory_strings: findings_dir.join("memory_strings.csv"),
            memory_triage: findings_dir.join("memory_triage.csv"),
            timeline_jsonl: timeline_dir.join("timeline.jsonl"),
            timeline_csv: timeline_dir.join("timeline.csv"),
            attack_chains: timeline_dir.join("attack_chains.md"),
            root,
            collection_dir,
            parsed_dir,
            enrich_dir,
            timeline_dir,
            rules_used_dir,
            runtime_dir,
            events_dir,
            containers_dir,
            evidence_pack_dir,
            findings_dir,
            evidence_dir,
            reports_dir,
            raw_dir,
        }
    }
}

/// Evidence output contains credentials, password hashes and raw event data.
/// Keep the directory private on Unix; Windows uses the inherited ACL and is
/// handled by the deployment account's ACL policy.
fn restrict_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let icacls = std::env::var_os("SystemRoot")
            .map(|root| Path::new(&root).join("System32").join("icacls.exe"))
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\icacls.exe"));
        let current_user = std::env::var("USERNAME").unwrap_or_default();
        // 机器/服务账户名(结尾 $,如 SYSTEM 会话下的 JEROME-XXX$)不是可授权主体,
        // 直接跳过用户条目,避免 icacls 解析主体失败。
        let user_grant = (!current_user.is_empty() && !current_user.ends_with('$'))
            .then(|| format!("{current_user}:F"));
        let run_icacls = |user: Option<&str>| -> std::io::Result<std::process::ExitStatus> {
            let mut command = std::process::Command::new(&icacls);
            command
                .arg(path)
                .args(["/inheritance:r", "/grant:r", "SYSTEM:F", "Administrators:F"]);
            if let Some(user) = user {
                command.arg(user);
            }
            command.status()
        };
        let ok = run_icacls(user_grant.as_deref())
            .map(|status| status.success())
            .unwrap_or(false)
            || run_icacls(None)
                .map(|status| status.success())
                .unwrap_or(false);
        if !ok {
            // 收权失败不中止取证(整次采集的价值高于权限收紧):结果目录保持父目录
            // 继承权限,写说明文件提示分析人员移交前手工收紧。
            let _ = std::fs::write(
                path.join("PERMISSION_WARNING.txt"),
                "dumpall: failed to restrict directory permissions via icacls. Access control falls back to permissions inherited from the parent directory. Manually restrict this directory before moving it off-host.\n",
            );
        }
    }
    let _ = path;
    Ok(())
}
