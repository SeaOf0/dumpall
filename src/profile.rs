use std::fmt;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ScanProfile {
    #[default]
    Quick,
    Web,
    WebDb,
    FullIr,
    Runtime,
    HostIr,
    ContainerIr,
    Triage,
}

impl ScanProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Web => "web",
            Self::WebDb => "web-db",
            Self::FullIr => "full-ir",
            Self::Runtime => "runtime",
            Self::HostIr => "host-ir",
            Self::ContainerIr => "container-ir",
            Self::Triage => "triage",
        }
    }

    pub fn capabilities(self) -> ProfileCapabilities {
        match self {
            Self::Quick => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: false,
                waf_logs: false,
                app_logs: false,
                static_scan: false,
                enrichment: false,
                timeline: false,
                sarif: false,
                runtime_scan: false,
                host_events: false,
                container: false,
                evidence_pack: false,
                host_artifacts: false,
            },
            Self::Web => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: false,
                waf_logs: true,
                app_logs: true,
                static_scan: false,
                enrichment: false,
                timeline: false,
                sarif: false,
                runtime_scan: false,
                host_events: false,
                container: false,
                evidence_pack: false,
                host_artifacts: false,
            },
            Self::WebDb => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: true,
                waf_logs: true,
                app_logs: true,
                static_scan: false,
                enrichment: false,
                timeline: false,
                sarif: false,
                runtime_scan: false,
                host_events: false,
                container: false,
                evidence_pack: false,
                host_artifacts: false,
            },
            Self::FullIr => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: true,
                waf_logs: true,
                app_logs: true,
                static_scan: true,
                enrichment: true,
                timeline: true,
                sarif: false,
                runtime_scan: false,
                host_events: false,
                container: false,
                evidence_pack: false,
                host_artifacts: true,
            },
            Self::Runtime => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: false,
                waf_logs: true,
                app_logs: true,
                static_scan: true,
                enrichment: false,
                timeline: true,
                sarif: false,
                runtime_scan: true,
                host_events: false,
                container: false,
                evidence_pack: false,
                host_artifacts: false,
            },
            Self::HostIr => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: false,
                waf_logs: false,
                app_logs: false,
                static_scan: false,
                enrichment: false,
                timeline: true,
                sarif: false,
                runtime_scan: false,
                host_events: true,
                container: false,
                evidence_pack: false,
                host_artifacts: true,
            },
            Self::Triage => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: true,
                waf_logs: true,
                app_logs: true,
                static_scan: true,
                enrichment: true,
                timeline: true,
                sarif: false,
                runtime_scan: true,
                host_events: true,
                container: true,
                evidence_pack: true,
                host_artifacts: true,
            },
            Self::ContainerIr => ProfileCapabilities {
                web_logs: true,
                host_context: true,
                database_logs: false,
                waf_logs: false,
                app_logs: true,
                static_scan: true,
                enrichment: false,
                timeline: true,
                sarif: false,
                runtime_scan: false,
                host_events: false,
                container: true,
                evidence_pack: false,
                host_artifacts: false,
            },
        }
    }
}

impl fmt::Display for ScanProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCapabilities {
    pub web_logs: bool,
    pub host_context: bool,
    pub database_logs: bool,
    pub waf_logs: bool,
    pub app_logs: bool,
    pub static_scan: bool,
    pub enrichment: bool,
    pub timeline: bool,
    pub sarif: bool,
    pub runtime_scan: bool,
    pub host_events: bool,
    pub container: bool,
    pub evidence_pack: bool,
    pub host_artifacts: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_profile_keeps_v1_default_boundary() {
        let capabilities = ScanProfile::Quick.capabilities();

        assert!(capabilities.web_logs);
        assert!(capabilities.host_context);
        assert!(!capabilities.database_logs);
        assert!(!capabilities.waf_logs);
        assert!(!capabilities.app_logs);
        assert!(!capabilities.static_scan);
        assert!(!capabilities.enrichment);
        assert!(!capabilities.timeline);
        assert!(!capabilities.runtime_scan);
        assert!(!capabilities.host_events);
        assert!(!capabilities.container);
    }

    #[test]
    fn full_ir_profile_declares_enhanced_boundaries() {
        let capabilities = ScanProfile::FullIr.capabilities();

        assert!(capabilities.database_logs);
        assert!(capabilities.waf_logs);
        assert!(capabilities.app_logs);
        assert!(capabilities.static_scan);
        assert!(capabilities.enrichment);
        assert!(capabilities.timeline);
        assert!(!capabilities.runtime_scan);
        assert!(!capabilities.host_events);
        assert!(!capabilities.sarif);
    }

    #[test]
    fn v12_profiles_declare_new_collector_boundaries() {
        assert!(ScanProfile::Runtime.capabilities().runtime_scan);
        assert!(ScanProfile::HostIr.capabilities().host_events);
        assert!(ScanProfile::ContainerIr.capabilities().container);
        assert!(ScanProfile::Runtime.capabilities().timeline);
        assert!(ScanProfile::HostIr.capabilities().timeline);
        assert!(ScanProfile::ContainerIr.capabilities().timeline);
    }
}
