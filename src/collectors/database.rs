use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::DbType;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const DISCOVERED_DB_LOG_HEADER: &str = "path,source,db_type,priority,exists,notes,evidence\n";

#[derive(Debug, Default)]
pub struct DatabaseDiscoveryStats {
    pub candidates: usize,
    pub existing: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredDbLogRow {
    pub path: String,
    pub source: String,
    pub db_type: String,
    pub priority: u8,
    pub exists: bool,
    pub notes: String,
    pub evidence: String,
}

pub fn collect(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<DatabaseDiscoveryStats> {
    let rows = discover_database_logs(resolved, layout);
    let stats = DatabaseDiscoveryStats {
        candidates: rows.len(),
        existing: rows.iter().filter(|row| row.exists).count(),
    };
    write_rows(&layout.discovered_db_logs, &rows)?;
    Ok(stats)
}

pub fn discover_database_logs(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
) -> Vec<DiscoveredDbLogRow> {
    let mut builder = DbDiscoveryBuilder::default();
    add_manual_paths(resolved, &mut builder);
    add_process_hints(resolved.db_type, layout, &mut builder);
    add_standard_paths(resolved.db_type, &mut builder);
    builder.finish()
}

fn add_manual_paths(resolved: &ResolvedRun, builder: &mut DbDiscoveryBuilder) {
    let db_type = resolved.db_type;
    for path in &resolved.db_log_paths {
        builder.path(
            path.clone(),
            "manual",
            db_type,
            10,
            "user supplied --db-log-path",
            "manual",
        );
    }
}

fn add_process_hints(db_type: DbType, layout: &OutputLayout, builder: &mut DbDiscoveryBuilder) {
    let Ok(processes) = fs::read_to_string(&layout.processes) else {
        return;
    };
    let lower = processes.to_ascii_lowercase();

    if db_type_matches(db_type, DbType::MySql)
        && (lower.contains("mysqld") || lower.contains("mariadb"))
    {
        add_mysql_standard_paths(builder, 40, "process hint: mysqld/mariadb");
        extract_option_paths(
            &processes,
            &[
                "--log-error=",
                "--general_log_file=",
                "--slow_query_log_file=",
            ],
        )
        .into_iter()
        .for_each(|path| {
            builder.path(
                path,
                "process",
                db_type_for_mysql_hint(db_type),
                25,
                "database process command line",
                "log option",
            );
        });
    }

    if db_type_matches(db_type, DbType::PostgreSql) && lower.contains("postgres") {
        add_postgresql_standard_paths(builder, 40, "process hint: postgres");
        extract_option_paths(&processes, &["log_directory="])
            .into_iter()
            .for_each(|path| {
                builder.path(
                    path,
                    "process",
                    DbType::PostgreSql,
                    25,
                    "database process command line",
                    "log_directory option",
                );
            });
    }

    if db_type_matches(db_type, DbType::Mssql)
        && (lower.contains("sqlservr") || lower.contains("mssql"))
    {
        add_mssql_standard_paths(builder, 40, "process hint: sqlservr");
    }
}

fn add_standard_paths(db_type: DbType, builder: &mut DbDiscoveryBuilder) {
    if db_type_matches(db_type, DbType::MySql) {
        add_mysql_standard_paths(builder, 80, "standard MySQL/MariaDB log path");
    }
    if db_type_matches(db_type, DbType::PostgreSql) {
        add_postgresql_standard_paths(builder, 80, "standard PostgreSQL log path");
    }
    if db_type_matches(db_type, DbType::Mssql) {
        add_mssql_standard_paths(builder, 80, "standard SQL Server log path");
    }
}

fn add_mysql_standard_paths(builder: &mut DbDiscoveryBuilder, priority: u8, evidence: &str) {
    for path in expand_wildcard_candidates(&mysql_standard_paths()) {
        builder.path(
            path,
            "standard",
            DbType::MySql,
            priority,
            evidence,
            "candidate_mysql_log_path",
        );
    }
}

fn add_postgresql_standard_paths(builder: &mut DbDiscoveryBuilder, priority: u8, evidence: &str) {
    for path in expand_wildcard_candidates(&postgresql_standard_paths()) {
        builder.path(
            path,
            "standard",
            DbType::PostgreSql,
            priority,
            evidence,
            "candidate_postgresql_log_path",
        );
    }
}

fn add_mssql_standard_paths(builder: &mut DbDiscoveryBuilder, priority: u8, evidence: &str) {
    for path in expand_wildcard_candidates(&mssql_standard_paths()) {
        builder.path(
            path,
            "standard",
            DbType::Mssql,
            priority,
            evidence,
            "candidate_mssql_log_path",
        );
    }
}

fn db_type_matches(selected: DbType, candidate: DbType) -> bool {
    selected == DbType::Auto
        || selected == candidate
        || (candidate == DbType::MySql && selected == DbType::MariaDb)
}

fn db_type_for_mysql_hint(selected: DbType) -> DbType {
    if selected == DbType::MariaDb {
        DbType::MariaDb
    } else {
        DbType::MySql
    }
}

fn extract_option_paths(processes: &str, prefixes: &[&str]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for token in processes.split_whitespace() {
        let token = token.trim_matches('"').trim_matches('\'');
        for prefix in prefixes {
            if let Some(value) = token.strip_prefix(prefix) {
                if !value.trim().is_empty() {
                    paths.push(PathBuf::from(value.trim_matches('"').trim_matches('\'')));
                }
            }
        }
    }
    paths
}

#[cfg(windows)]
fn mysql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\ProgramData\MySQL\MySQL Server 8.0\Data"),
        PathBuf::from(r"C:\ProgramData\MySQL\MySQL Server 5.7\Data"),
        PathBuf::from(r"C:\ProgramData\MySQL\MySQL Server*\Data\*.err"),
        PathBuf::from(r"C:\ProgramData\MariaDB"),
    ]
}

#[cfg(unix)]
fn mysql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/log/mysql/error.log"),
        PathBuf::from("/var/log/mysqld.log"),
        PathBuf::from("/var/log/mysql"),
        PathBuf::from("/var/log/mariadb"),
        PathBuf::from("/var/lib/mysql"),
        PathBuf::from("/var/lib/mysql/*.err"),
        PathBuf::from("/usr/local/mysql/data"),
    ]
}

#[cfg(windows)]
fn postgresql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Program Files\PostgreSQL\16\data\log"),
        PathBuf::from(r"C:\Program Files\PostgreSQL\15\data\log"),
        PathBuf::from(r"C:\Program Files\PostgreSQL\*\data\log\*.log"),
    ]
}

#[cfg(unix)]
fn postgresql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/log/postgresql/postgresql-15.log"),
        PathBuf::from("/var/log/postgresql/postgresql-16.log"),
        PathBuf::from("/var/log/postgresql/postgresql-*.log"),
        PathBuf::from("/var/log/postgresql"),
        PathBuf::from("/var/lib/pgsql/data/log"),
        PathBuf::from("/var/lib/pgsql/data/log/*.log"),
        PathBuf::from("/var/lib/postgresql/data/log"),
    ]
}

#[cfg(windows)]
fn mssql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log"),
        PathBuf::from(r"C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Log"),
        PathBuf::from(r"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Log"),
        PathBuf::from(r"C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*"),
    ]
}

#[cfg(unix)]
fn mssql_standard_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/opt/mssql/log"),
        PathBuf::from("/var/opt/mssql/log/errorlog"),
    ]
}

/// 展开候选路径清单：含 '*' 的模式按目录逐段展开（每段最多一个 '*'，
/// 前缀+后缀不区分大小写匹配），只追加实际存在的路径；无 '*' 的字面路径
/// 原样透传，存在性仍由 DbDiscoveryBuilder 统一标注，发现语义不变。
fn expand_wildcard_candidates(patterns: &[PathBuf]) -> Vec<PathBuf> {
    let mut expanded = Vec::new();
    for pattern in patterns {
        if !pattern.to_string_lossy().contains('*') {
            expanded.push(pattern.clone());
            continue;
        }
        expanded.extend(expand_one_pattern(pattern));
    }
    expanded
}

fn expand_one_pattern(pattern: &Path) -> Vec<PathBuf> {
    use std::path::Component;
    let mut components: Vec<Component<'_>> = pattern.components().collect();

    // 前导盘符/根目录构造绝对基路径（Windows "C:\"、Unix "/"）。
    let mut base = PathBuf::new();
    while let Some(component) = components.first().copied() {
        match component {
            Component::Prefix(prefix) => {
                base = PathBuf::from(prefix.as_os_str());
            }
            Component::RootDir => {
                if base.as_os_str().is_empty() {
                    base = PathBuf::from("/");
                } else {
                    base = PathBuf::from(format!(
                        "{}{}",
                        base.display(),
                        std::path::MAIN_SEPARATOR
                    ));
                }
            }
            _ => break,
        }
        components.remove(0);
    }

    let mut current = vec![base];
    for component in components {
        let Some(segment) = component.as_os_str().to_str() else {
            return Vec::new();
        };
        if !segment.contains('*') {
            for path in &mut current {
                path.push(segment);
            }
            continue;
        }
        let mut next = Vec::new();
        for directory in &current {
            let Ok(entries) = fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if !(file_type.is_file() || file_type.is_dir()) {
                    continue;
                }
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                if segment_matches(name, segment) {
                    next.push(directory.join(name));
                }
            }
        }
        if next.is_empty() {
            return Vec::new();
        }
        current = next;
    }
    current
}

fn segment_matches(name: &str, pattern: &str) -> bool {
    match pattern.split_once('*') {
        None => name.eq_ignore_ascii_case(pattern),
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name[..prefix.len()].eq_ignore_ascii_case(prefix)
                && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        }
    }
}

#[derive(Default)]
struct DbDiscoveryBuilder {
    rows: Vec<DiscoveredDbLogRow>,
    seen: HashSet<String>,
}

impl DbDiscoveryBuilder {
    fn path(
        &mut self,
        path: PathBuf,
        source: impl Into<String>,
        db_type: DbType,
        priority: u8,
        evidence: impl Into<String>,
        notes: impl Into<String>,
    ) {
        let key = normalize_key(&path);
        if !self.seen.insert(format!("{}|{}", db_type.as_str(), key)) {
            return;
        }
        self.rows.push(DiscoveredDbLogRow {
            exists: path.exists(),
            path: path.display().to_string(),
            source: source.into(),
            db_type: db_type.as_str().to_string(),
            priority,
            notes: notes.into(),
            evidence: evidence.into(),
        });
    }

    fn finish(mut self) -> Vec<DiscoveredDbLogRow> {
        self.rows.sort_by_key(|row| row.priority);
        self.rows
    }
}

fn normalize_key(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn write_rows(path: &Path, rows: &[DiscoveredDbLogRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, DISCOVERED_DB_LOG_HEADER)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ContainerRuntime, OutputFormat, PackFormat, RunMode, RuntimeTarget, TimeRange,
    };
    use crate::profile::ScanProfile;
    use crate::safety::SafetyLimits;

    #[test]
    fn wildcard_expansion_appends_only_existing_paths() {
        let root = crate::unique_test_dir("db-wildcard");
        let data_dir = root.join("MySQL Server 8.0").join("Data");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("mysql.err"), "").unwrap();
        fs::write(data_dir.join("mysql-error.log"), "").unwrap();

        // 目录通配 + 文件通配：命中存在的 .err，无命中返回空。
        let pattern = root.join("MySQL Server*").join("Data").join("*.err");
        let expanded = expand_wildcard_candidates(&[pattern.clone(), root.join("literal.log")]);
        assert_eq!(
            expanded,
            vec![data_dir.join("mysql.err"), root.join("literal.log")]
        );

        let missing = root.join("MySQL Server*").join("Data").join("*.trace");
        assert!(expand_wildcard_candidates(&[missing]).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn segment_matcher_is_case_insensitive_prefix_suffix() {
        assert!(segment_matches("MSSQL16.MSSQLSERVER", "MSSQL*"));
        assert!(segment_matches("ERRORLOG.1", "ERRORLOG*"));
        assert!(segment_matches("postgresql-15.log", "postgresql-*.log"));
        assert!(!segment_matches("postgresql.log", "postgresql-*.log"));
        assert!(segment_matches("errorlog", "ERRORLOG"));
    }

    #[test]
    fn manual_db_log_path_has_high_priority() {
        let root = crate::unique_test_dir("db-discovery");
        fs::create_dir_all(&root).unwrap();
        let db_log = root.join("mysql.log");
        fs::write(&db_log, "").unwrap();
        let layout = OutputLayout::from_root(root.join("results"));
        let resolved = ResolvedRun {
            mode: RunMode::Collect,
            started_at: "2026-05-15T00:00:00Z".to_string(),
            time_range: TimeRange {
                mode: "recent_hours".to_string(),
                since: None,
                until: None,
                hours: Some(5),
            },
            updatetime: false,
            web_paths: Vec::new(),
            log_paths: Vec::new(),
            db_type: DbType::MySql,
            db_log_paths: vec![db_log.clone()],
            waf_log_paths: Vec::new(),
            app_log_paths: Vec::new(),
            middleware: None,
            profile: ScanProfile::Quick,
            timeline: false,
            sarif: false,
            baseline: None,
            static_scan: false,
            yara_rules: Vec::new(),
            trusted_proxy: Vec::new(),
            geoip_db: None,
            ioc: Vec::new(),
            runtime_scan: false,
            runtime_target: RuntimeTarget::Auto,
            java_home: None,
            tomcat_base: Vec::new(),
            spring_app_path: Vec::new(),
            iis_config: None,
            evtx_paths: Vec::new(),
            journal_paths: Vec::new(),
            audit_log_paths: Vec::new(),
            container_runtime: ContainerRuntime::Auto,
            container_log_paths: Vec::new(),
            k8s_node_paths: Vec::new(),
            evidence_pack: false,
            pack_format: PackFormat::Zip,
            component_baseline: None,
            runtime_active_check: false,
            max_event_records: 200_000,
            output_dir: root.join("results"),
            formats: vec![
                OutputFormat::Jsonl,
                OutputFormat::Csv,
                OutputFormat::Markdown,
            ],
            full_scan: false,
            max_static_file_size_mb: 10,
            max_yara_file_size_mb: 20,
            safety: SafetyLimits {
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
            event_cutoff: None,
        };

        let rows = discover_database_logs(&resolved, &layout);

        assert_eq!(rows.first().unwrap().priority, 10);
        assert_eq!(rows.first().unwrap().path, db_log.display().to_string());
        assert_eq!(rows.first().unwrap().db_type, "mysql");

        fs::remove_dir_all(root).unwrap();
    }
}
