use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{DumpallError, Result};
use crate::output::manifest::RunStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Scan,
    Collect,
    Analyze,
    Triage,
    Export,
}

impl RunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Collect => "collect",
            Self::Analyze => "analyze",
            Self::Triage => "triage",
            Self::Export => "export",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Jsonl,
    Csv,
    #[serde(rename = "md")]
    Markdown,
    Html,
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
            Self::Markdown => "md",
            Self::Html => "html",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "jsonl" => Ok(Self::Jsonl),
            "csv" => Ok(Self::Csv),
            "md" | "markdown" => Ok(Self::Markdown),
            "html" => Ok(Self::Html),
            other => Err(DumpallError::invalid_argument(
                "format",
                format!("unsupported output format `{other}`"),
            )),
        }
    }

    pub fn parse_all(values: &[String]) -> Result<Vec<Self>> {
        if values.is_empty() {
            return Ok(vec![Self::Jsonl, Self::Csv, Self::Markdown, Self::Html]);
        }
        values.iter().map(|value| Self::parse(value)).collect()
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MiddlewareKind {
    Nginx,
    Apache,
    Tomcat,
    Iis,
    Weblogic,
    Jboss,
    Spring,
    Django,
    Flask,
    Node,
    Php,
    #[serde(rename = "aspnet")]
    AspNet,
    Caddy,
}

impl MiddlewareKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "nginx" => Ok(Self::Nginx),
            "apache" | "httpd" => Ok(Self::Apache),
            "tomcat" => Ok(Self::Tomcat),
            "iis" => Ok(Self::Iis),
            "weblogic" => Ok(Self::Weblogic),
            "jboss" | "wildfly" => Ok(Self::Jboss),
            "spring" | "springboot" | "spring-boot" => Ok(Self::Spring),
            "django" => Ok(Self::Django),
            "flask" => Ok(Self::Flask),
            "node" | "express" => Ok(Self::Node),
            "php" | "php-fpm" => Ok(Self::Php),
            "aspnet" | "asp.net" | "aspnetcore" | "asp.net-core" => Ok(Self::AspNet),
            "caddy" => Ok(Self::Caddy),
            other => Err(DumpallError::invalid_argument(
                "middleware",
                format!("unsupported middleware `{other}`"),
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Apache => "apache",
            Self::Tomcat => "tomcat",
            Self::Iis => "iis",
            Self::Weblogic => "weblogic",
            Self::Jboss => "jboss",
            Self::Spring => "spring",
            Self::Django => "django",
            Self::Flask => "flask",
            Self::Node => "node",
            Self::Php => "php",
            Self::AspNet => "aspnet",
            Self::Caddy => "caddy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbType {
    Auto,
    MySql,
    MariaDb,
    PostgreSql,
    Mssql,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTarget {
    Auto,
    Java,
    Iis,
    #[serde(rename = "aspnet")]
    AspNet,
}

impl RuntimeTarget {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "java" => Ok(Self::Java),
            "iis" => Ok(Self::Iis),
            "aspnet" | "asp.net" | "aspnetcore" | "asp.net-core" => Ok(Self::AspNet),
            other => Err(DumpallError::invalid_argument(
                "runtime-target",
                format!("unsupported runtime target `{other}`"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Java => "java",
            Self::Iis => "iis",
            Self::AspNet => "aspnet",
        }
    }
}

impl fmt::Display for RuntimeTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    Auto,
    Docker,
    Containerd,
}

impl ContainerRuntime {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "docker" => Ok(Self::Docker),
            "containerd" => Ok(Self::Containerd),
            other => Err(DumpallError::invalid_argument(
                "container-runtime",
                format!("unsupported container runtime `{other}`"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Docker => "docker",
            Self::Containerd => "containerd",
        }
    }
}

impl fmt::Display for ContainerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackFormat {
    Zip,
    Tar,
}

impl PackFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "zip" => Ok(Self::Zip),
            "tar" => Ok(Self::Tar),
            other => Err(DumpallError::invalid_argument(
                "pack-format",
                format!("unsupported evidence pack format `{other}`"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
        }
    }
}

impl fmt::Display for PackFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl DbType {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "mysql" => Ok(Self::MySql),
            "mariadb" | "maria-db" => Ok(Self::MariaDb),
            "postgresql" | "postgres" | "pgsql" => Ok(Self::PostgreSql),
            "mssql" | "sqlserver" | "sql-server" | "sql_server" => Ok(Self::Mssql),
            other => Err(DumpallError::invalid_argument(
                "db-type",
                format!("unsupported database type `{other}`"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::MySql => "mysql",
            Self::MariaDb => "mariadb",
            Self::PostgreSql => "postgresql",
            Self::Mssql => "mssql",
        }
    }

    pub fn is_auto(self) -> bool {
        self == Self::Auto
    }
}

impl fmt::Display for DbType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u16) -> Self {
        match score {
            0..=29 => Self::Info,
            30..=49 => Self::Low,
            50..=69 => Self::Medium,
            70..=89 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceQuality {
    #[serde(rename = "Q1")]
    #[default]
    Q1,
    #[serde(rename = "Q2")]
    Q2,
    #[serde(rename = "Q3")]
    Q3,
    #[serde(rename = "Q4")]
    Q4,
    #[serde(rename = "Q5")]
    Q5,
}

impl EvidenceQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Q1 => "Q1",
            Self::Q2 => "Q2",
            Self::Q3 => "Q3",
            Self::Q4 => "Q4",
            Self::Q5 => "Q5",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Q1 => "direct evidence",
            Self::Q2 => "strong correlation evidence",
            Self::Q3 => "weak correlation evidence",
            Self::Q4 => "environment context",
            Self::Q5 => "collection gap",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionCoverageStatus {
    Collected,
    Partial,
    NotCollected,
    Unsupported,
}

impl CollectionCoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collected => "collected",
            Self::Partial => "partial",
            Self::NotCollected => "not_collected",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGap {
    pub gap_id: String,
    pub timestamp: String,
    pub source: String,
    pub path: String,
    pub operation: String,
    pub message: String,
    pub detail: Option<String>,
    pub coverage_status: CollectionCoverageStatus,
    pub confidence: Confidence,
    pub evidence_quality: EvidenceQuality,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionCoverage {
    pub scope: String,
    pub status: CollectionCoverageStatus,
    pub expected: bool,
    pub records_collected: u64,
    pub gaps: Vec<EvidenceGap>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub base_rule_score: i16,
    pub context_score: i16,
    pub correlation_score: i16,
    pub enrichment_score: i16,
    pub anomaly_score: i16,
    pub runtime_score: i16,
    pub host_event_score: i16,
    pub container_score: i16,
    pub evidence_quality_score: i16,
    pub evidence_gap_discount: i16,
    pub allowlist_discount: i16,
    pub noise_discount: i16,
}

impl ScoreBreakdown {
    pub fn from_base(base_rule_score: u16) -> Self {
        Self {
            base_rule_score: base_rule_score.min(100) as i16,
            ..Self::default()
        }
    }

    pub fn from_final_score(score: u16) -> Self {
        Self::from_base(score)
    }

    pub fn add_context(&mut self, value: i16) {
        self.context_score = self.context_score.saturating_add(value);
    }

    pub fn add_correlation(&mut self, value: u16) {
        self.correlation_score = self.correlation_score.saturating_add(value as i16);
    }

    pub fn add_enrichment(&mut self, value: u16) {
        self.enrichment_score = self.enrichment_score.saturating_add(value as i16);
    }

    pub fn add_noise_discount(&mut self, value: u16) {
        self.noise_discount = self.noise_discount.saturating_sub(value as i16);
    }

    pub fn add_evidence_gap_discount(&mut self, value: u16) {
        self.evidence_gap_discount = self.evidence_gap_discount.saturating_sub(value as i16);
    }
}

fn is_default_score_breakdown(value: &ScoreBreakdown) -> bool {
    value.base_rule_score == 0
        && value.context_score == 0
        && value.correlation_score == 0
        && value.enrichment_score == 0
        && value.anomaly_score == 0
        && value.runtime_score == 0
        && value.host_event_score == 0
        && value.container_score == 0
        && value.evidence_quality_score == 0
        && value.evidence_gap_discount == 0
        && value.allowlist_discount == 0
        && value.noise_discount == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub value: u16,
    pub severity: Severity,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub breakdown: ScoreBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub mode: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub hours: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub source_file: String,
    pub line_number: Option<u64>,
    pub raw_hash: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpLogEvent {
    pub timestamp: Option<String>,
    pub source_file: String,
    pub line_number: u64,
    pub remote_ip: Option<String>,
    pub xff_ip: Option<String>,
    pub inferred_client_ip: Option<String>,
    pub proxy_ip: Option<String>,
    pub client_ip_source: Option<String>,
    pub method: Option<String>,
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub uri_path: Option<String>,
    pub uri_query: Option<String>,
    pub status: Option<u16>,
    pub bytes_sent: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub request_time: Option<f64>,
    pub upstream_status: Option<String>,
    pub upstream_time: Option<f64>,
    pub raw_hash: String,
    pub parser_name: String,
    pub parse_confidence: f32,
}

impl HttpLogEvent {
    pub fn effective_remote_ip(&self) -> Option<&str> {
        self.inferred_client_ip
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| self.remote_ip.as_deref().filter(|value| !value.is_empty()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbLogEvent {
    pub timestamp: Option<String>,
    pub source_file: String,
    pub line_number: u64,
    pub db_type: String,
    pub db_instance: Option<String>,
    pub db_user: Option<String>,
    pub db_name: Option<String>,
    pub client_ip: Option<String>,
    pub client_port: Option<u16>,
    pub session_id: Option<String>,
    pub statement_type: Option<String>,
    pub statement_summary: Option<String>,
    pub duration_ms: Option<f64>,
    pub rows: Option<u64>,
    pub error_code: Option<String>,
    pub severity: Option<String>,
    pub raw_hash: String,
    pub parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafLogEvent {
    pub timestamp: Option<String>,
    pub source_file: String,
    pub line_number: u64,
    pub vendor: Option<String>,
    pub action: Option<String>,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub client_ip: Option<String>,
    pub proxy_ip: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub score: Option<f64>,
    pub raw_hash: String,
    pub parser_name: String,
    pub parse_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLogEvent {
    pub timestamp: Option<String>,
    pub source_file: String,
    pub line_number: u64,
    pub framework: Option<String>,
    pub level: Option<String>,
    pub logger: Option<String>,
    pub exception_type: Option<String>,
    pub message_summary: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub http_path: Option<String>,
    pub user_summary: Option<String>,
    pub raw_hash: String,
    pub parser_name: String,
    pub parse_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsEvent {
    pub event_id: String,
    pub timestamp: Option<String>,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub event_code: Option<String>,
    pub computer: Option<String>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<String>,
    pub parent_process_name: Option<String>,
    pub command_line_summary: Option<String>,
    pub source_ip: Option<String>,
    pub target_user: Option<String>,
    pub service_name: Option<String>,
    pub task_name: Option<String>,
    pub object_path: Option<String>,
    pub action: Option<String>,
    pub result: Option<String>,
    pub severity: Option<String>,
    pub raw_hash: String,
    pub parser_confidence: f32,
    pub source_file: String,
    pub line_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxEvent {
    pub event_id: String,
    pub timestamp: Option<String>,
    pub source: Option<String>,
    pub unit: Option<String>,
    pub user: Option<String>,
    pub uid: Option<String>,
    pub pid: Option<String>,
    pub ppid: Option<String>,
    pub process_name: Option<String>,
    pub command_line_summary: Option<String>,
    pub cwd: Option<String>,
    pub src_ip: Option<String>,
    pub tty: Option<String>,
    pub session: Option<String>,
    pub action: Option<String>,
    pub object_path: Option<String>,
    pub result: Option<String>,
    pub raw_hash: String,
    pub parser_confidence: f32,
    pub source_file: String,
    pub line_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub container_id: String,
    pub container_name: String,
    pub runtime: String,
    pub image: String,
    pub image_id: String,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub process_id: Option<String>,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub is_privileged: bool,
    pub host_pid: bool,
    pub host_network: bool,
    pub risk_flags: String,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImageRecord {
    pub image: String,
    pub image_id: String,
    pub created_at: Option<String>,
    pub size: Option<u64>,
    pub repo_tags: Vec<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMountRecord {
    pub container_id: String,
    pub container_name: String,
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub is_sensitive: bool,
    pub risk_flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerNetworkRecord {
    pub container_id: String,
    pub container_name: String,
    pub network: String,
    pub ip_address: String,
    pub ports: String,
    pub host_network: bool,
    pub risk_flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLogEvent {
    pub event_id: String,
    pub timestamp: Option<String>,
    pub runtime: String,
    pub container_id: Option<String>,
    pub container_name: Option<String>,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub stream: Option<String>,
    pub message_summary: String,
    pub source_file: String,
    pub line_number: u64,
    pub raw_hash: String,
    pub parser_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionError {
    pub timestamp: String,
    pub source: String,
    pub path: String,
    pub operation: String,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseError {
    pub source_file: String,
    pub line_number: u64,
    pub parser_name: String,
    pub message: String,
    pub raw_hash: String,
    pub raw_sample: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub timestamp: Option<String>,
    pub severity: Severity,
    pub score: u16,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence_quality: EvidenceQuality,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_quality_basis: String,
    #[serde(default, skip_serializing_if = "is_default_score_breakdown")]
    pub score_breakdown: ScoreBreakdown,
    pub category: String,
    pub rule_id: String,
    pub rule_name: String,
    pub source_type: String,
    pub source_file: Option<String>,
    pub line_number: Option<u64>,
    pub remote_ip: Option<String>,
    pub method: Option<String>,
    pub uri_path: Option<String>,
    pub status: Option<u16>,
    pub evidence_summary: String,
    pub raw_hash: Option<String>,
    pub related_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_chain_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_chain_basis: Option<String>,
    pub recommendation: String,
}

impl Finding {
    pub fn with_default_assessment(mut self) -> Self {
        self.assign_default_v12_assessment();
        self
    }

    pub fn assign_default_v12_assessment(&mut self) {
        if self.evidence_quality_basis.is_empty() {
            self.evidence_quality = default_evidence_quality_for_source(&self.source_type);
            self.evidence_quality_basis = format!(
                "{} {} from {} evidence",
                self.evidence_quality.as_str(),
                self.evidence_quality.description(),
                self.source_type
            );
        }
        self.confidence = confidence_for(self.score, self.evidence_quality);
    }

    pub fn set_evidence_quality(&mut self, quality: EvidenceQuality, basis: impl Into<String>) {
        self.evidence_quality = quality;
        self.evidence_quality_basis = basis.into();
        self.confidence = confidence_for(self.score, self.evidence_quality);
    }
}

pub fn default_evidence_quality_for_source(source_type: &str) -> EvidenceQuality {
    match source_type {
        "evidence_gap" => EvidenceQuality::Q5,
        "ioc" | "enrichment" => EvidenceQuality::Q4,
        _ => EvidenceQuality::Q1,
    }
}

pub fn confidence_for(score: u16, quality: EvidenceQuality) -> Confidence {
    match quality {
        EvidenceQuality::Q5 => Confidence::High,
        EvidenceQuality::Q4 => {
            if score >= 50 {
                Confidence::Medium
            } else {
                Confidence::Low
            }
        }
        EvidenceQuality::Q3 => {
            if score >= 70 {
                Confidence::Medium
            } else {
                Confidence::Low
            }
        }
        EvidenceQuality::Q2 => {
            if score >= 50 {
                Confidence::High
            } else {
                Confidence::Medium
            }
        }
        EvidenceQuality::Q1 => {
            if score >= 90 {
                Confidence::High
            } else if score >= 50 {
                Confidence::Medium
            } else {
                Confidence::Low
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPlan {
    pub command: String,
    pub dry_run: bool,
    pub time_range: TimeRange,
    pub updatetime: bool,
    pub web_paths: Vec<String>,
    pub log_paths: Vec<String>,
    pub db_type: String,
    pub db_log_paths: Vec<String>,
    pub waf_log_paths: Vec<String>,
    pub app_log_paths: Vec<String>,
    pub middleware: Option<String>,
    pub output_dir: String,
    pub formats: Vec<String>,
    pub full_scan: bool,
    pub profile: String,
    pub timeline: bool,
    pub sarif: bool,
    pub baseline: Option<String>,
    pub static_scan: bool,
    pub yara_rules: Vec<String>,
    pub trusted_proxy: Vec<String>,
    pub geoip_db: Option<String>,
    pub ioc: Vec<String>,
    pub runtime_scan: bool,
    pub runtime_target: String,
    pub java_home: Option<String>,
    pub tomcat_base: Vec<String>,
    pub spring_app_path: Vec<String>,
    pub iis_config: Option<String>,
    pub evtx_path: Vec<String>,
    pub journal_path: Vec<String>,
    pub audit_log_path: Vec<String>,
    pub container_enabled: bool,
    pub container_runtime: String,
    pub container_log_path: Vec<String>,
    pub k8s_node_path: Vec<String>,
    pub evidence_pack: bool,
    pub pack_format: String,
    pub component_baseline: Option<String>,
    pub runtime_active_check: bool,
    pub memory_triage: bool,
    pub max_event_records: u64,
    pub collector_plans: Vec<crate::collector_trait::CollectorPlanSummary>,
    pub max_cpu_percent: u8,
    pub threads: usize,
    pub max_file_size_mb: u64,
    pub max_static_file_size_mb: u64,
    pub max_yara_file_size_mb: u64,
    pub max_depth: usize,
    pub redact: bool,
    pub offline: bool,
    pub rules: Vec<String>,
    pub allowlist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub tool_version: String,
    pub command: String,
    pub started_at: String,
    pub finished_at: String,
    pub output_dir: String,
    pub privilege: String,
    pub offline: bool,
    pub redact: bool,
    pub formats: Vec<String>,
    pub time_range: TimeRange,
    pub files_scanned: u64,
    pub lines_parsed: u64,
    pub findings_count: usize,
    pub collection_errors: usize,
    pub parse_errors: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RunSummaryMetrics {
    pub stats: RunStats,
    pub findings_count: usize,
    pub collection_errors: usize,
    pub parse_errors: usize,
    pub notes: Vec<String>,
}

impl RunSummary {
    pub fn for_run(
        version: &str,
        resolved: &crate::config::ResolvedRun,
        preflight: &crate::preflight::PreflightReport,
        layout: &crate::output::paths::OutputLayout,
        metrics: RunSummaryMetrics,
    ) -> Self {
        Self {
            tool_version: version.to_string(),
            command: resolved.mode.as_str().to_string(),
            started_at: resolved.started_at.clone(),
            finished_at: crate::time_utils::now_iso(),
            output_dir: layout.root.display().to_string(),
            privilege: preflight.privilege.clone(),
            offline: resolved.safety.offline,
            redact: resolved.safety.redact,
            formats: resolved
                .formats
                .iter()
                .map(|format| format.as_str().to_string())
                .collect(),
            time_range: resolved.time_range.clone(),
            files_scanned: metrics.stats.files_scanned,
            lines_parsed: metrics.stats.lines_parsed,
            findings_count: metrics.findings_count,
            collection_errors: metrics.collection_errors,
            parse_errors: metrics.parse_errors,
            notes: metrics.notes,
        }
    }

    pub fn for_empty_run(
        version: &str,
        resolved: &crate::config::ResolvedRun,
        preflight: &crate::preflight::PreflightReport,
        layout: &crate::output::paths::OutputLayout,
        stats: RunStats,
        note: impl Into<String>,
    ) -> Self {
        Self::for_run(
            version,
            resolved,
            preflight,
            layout,
            RunSummaryMetrics {
                stats,
                findings_count: 0,
                collection_errors: 0,
                parse_errors: 0,
                notes: vec![note.into()],
            },
        )
    }
}

pub fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}
