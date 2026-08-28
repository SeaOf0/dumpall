pub mod apache;
pub mod iis;
pub mod model;
pub mod nginx;
pub mod process;
pub mod tomcat;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::MiddlewareKind;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use model::{DiscoveredLogRow, DiscoveryResult, MiddlewareRow, WebRootRow};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub fn discover(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<DiscoveryResult> {
    let mut builder = DiscoveryBuilder::default();
    add_manual_paths(resolved, &mut builder);
    add_process_hints(layout, &mut builder);
    add_config_hints(&mut builder);
    add_standard_paths(resolved.middleware.as_ref(), &mut builder);

    let result = builder.finish();
    writers::write_csv_serialize(&layout.middleware, &result.middleware)?;
    writers::write_csv_serialize(&layout.web_roots, &result.web_roots)?;
    writers::write_csv_serialize(&layout.discovered_logs, &result.logs)?;
    Ok(result)
}

fn add_manual_paths(resolved: &ResolvedRun, builder: &mut DiscoveryBuilder) {
    let middleware = resolved.middleware.as_ref().map(MiddlewareKind::as_str);
    for path in &resolved.web_paths {
        builder.web_root(
            path.clone(),
            "manual",
            middleware,
            10,
            "user supplied --web-path",
            "manual",
        );
    }
    for path in &resolved.log_paths {
        builder.log_path(
            path.clone(),
            "manual",
            middleware,
            10,
            "user supplied --log-path",
            "manual",
        );
    }
}

fn add_process_hints(layout: &OutputLayout, builder: &mut DiscoveryBuilder) {
    let Ok(processes) = fs::read_to_string(&layout.processes) else {
        return;
    };
    process::discover_from_process_text(&processes, builder);
}

fn add_config_hints(builder: &mut DiscoveryBuilder) {
    for path in standard_config_paths() {
        let Ok(content) = read_small_text_file(&path) else {
            continue;
        };
        let source = format!("config:{}", path.display());
        match infer_config_kind(&path) {
            Some(MiddlewareKind::Nginx) => nginx::discover_from_config(&content, &path, builder),
            Some(MiddlewareKind::Apache) => apache::discover_from_config(&content, &path, builder),
            Some(MiddlewareKind::Tomcat) => tomcat::discover_from_config(&content, &path, builder),
            Some(MiddlewareKind::Iis) => iis::discover_from_config(&content, &path, builder),
            _ => {}
        }
        // MiddlewareKind 没有 Unknown 变体(model.rs 不在本次修改范围),
        // 未知类型暂按 Nginx 兜底:nginx 是 unix 标准路径里最常见的形态,
        // 行内容解析失败时只记一行 middleware 候选,不影响其它路径线索。
        builder.middleware(
            infer_config_kind(&path).unwrap_or(MiddlewareKind::Nginx),
            source,
            60,
            "configuration file was readable",
        );
    }
}

fn add_standard_paths(filter: Option<&MiddlewareKind>, builder: &mut DiscoveryBuilder) {
    for kind in [
        MiddlewareKind::Nginx,
        MiddlewareKind::Apache,
        MiddlewareKind::Tomcat,
        MiddlewareKind::Iis,
    ] {
        if filter.map(|selected| selected != &kind).unwrap_or(false) {
            continue;
        }
        match kind {
            MiddlewareKind::Nginx => nginx::add_standard_paths(builder),
            MiddlewareKind::Apache => apache::add_standard_paths(builder),
            MiddlewareKind::Tomcat => tomcat::add_standard_paths(builder),
            MiddlewareKind::Iis => iis::add_standard_paths(builder),
            _ => {}
        }
    }
}

fn read_small_text_file(path: &Path) -> std::io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration file exceeds size limit",
        ));
    }
    fs::read_to_string(path)
}

fn infer_config_kind(path: &Path) -> Option<MiddlewareKind> {
    let text = path.display().to_string().to_ascii_lowercase();
    if text.contains("nginx") {
        Some(MiddlewareKind::Nginx)
    } else if text.contains("apache") || text.contains("httpd") {
        Some(MiddlewareKind::Apache)
    } else if text.contains("tomcat") || text.ends_with("server.xml") {
        Some(MiddlewareKind::Tomcat)
    } else if text.contains("applicationhost.config") || text.contains("inetsrv") {
        Some(MiddlewareKind::Iis)
    } else {
        None
    }
}

#[cfg(windows)]
fn standard_config_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\nginx\conf\nginx.conf"),
        PathBuf::from(r"C:\Apache24\conf\httpd.conf"),
        PathBuf::from(r"C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\server.xml"),
        PathBuf::from(r"C:\Windows\System32\inetsrv\config\applicationHost.config"),
    ]
}

#[cfg(unix)]
fn standard_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/etc/nginx/nginx.conf"),
        PathBuf::from("/etc/nginx/conf.d/default.conf"),
        PathBuf::from("/etc/apache2/apache2.conf"),
        PathBuf::from("/etc/httpd/conf/httpd.conf"),
        PathBuf::from("/opt/tomcat/conf/server.xml"),
    ];
    // conf.d / sites-enabled 目录下的片段配置逐个展开;
    // /etc/httpd(RHEL 系)与 /etc/nginx/conf.d 补齐发行版差异。
    for dir in [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/etc/apache2/sites-enabled",
        "/etc/httpd",
        "/etc/httpd/conf",
        "/etc/httpd/conf.d",
    ] {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("conf") {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

#[derive(Default)]
pub struct DiscoveryBuilder {
    middleware: Vec<MiddlewareRow>,
    web_roots: Vec<WebRootRow>,
    logs: Vec<DiscoveredLogRow>,
    seen_middleware: HashSet<String>,
    seen_web_roots: HashSet<String>,
    seen_logs: HashSet<String>,
}

impl DiscoveryBuilder {
    pub fn middleware(
        &mut self,
        kind: MiddlewareKind,
        source: impl Into<String>,
        confidence: u8,
        evidence: impl Into<String>,
    ) {
        let source = source.into();
        let evidence = evidence.into();
        let key = format!("{}|{}|{}", kind.as_str(), source, evidence).to_ascii_lowercase();
        if self.seen_middleware.insert(key) {
            self.middleware.push(MiddlewareRow {
                kind: kind.as_str().to_string(),
                source,
                evidence,
                confidence,
                notes: "candidate_middleware".to_string(),
            });
        }
    }

    pub fn web_root(
        &mut self,
        path: PathBuf,
        source: impl Into<String>,
        middleware: Option<&str>,
        priority: u8,
        evidence: impl Into<String>,
        notes: impl Into<String>,
    ) {
        let key = normalize_key(&path);
        if !self.seen_web_roots.insert(key) {
            return;
        }
        let exists = path.exists();
        let readable = path.read_dir().is_ok();
        self.web_roots.push(WebRootRow {
            path: path.display().to_string(),
            source: source.into(),
            middleware: middleware.unwrap_or("").to_string(),
            priority,
            exists,
            readable,
            notes: notes.into(),
            evidence: evidence.into(),
        });
    }

    pub fn log_path(
        &mut self,
        path: PathBuf,
        source: impl Into<String>,
        middleware: Option<&str>,
        priority: u8,
        evidence: impl Into<String>,
        notes: impl Into<String>,
    ) {
        let key = normalize_key(&path);
        if !self.seen_logs.insert(key) {
            return;
        }
        self.logs.push(DiscoveredLogRow {
            exists: path.exists(),
            path: path.display().to_string(),
            source: source.into(),
            middleware: middleware.unwrap_or("").to_string(),
            priority,
            notes: notes.into(),
            evidence: evidence.into(),
        });
    }

    pub fn finish(mut self) -> DiscoveryResult {
        self.web_roots.sort_by_key(|row| row.priority);
        self.logs.sort_by_key(|row| row.priority);
        self.middleware.sort_by_key(|row| row.kind.clone());
        DiscoveryResult {
            middleware: self.middleware,
            web_roots: self.web_roots,
            logs: self.logs,
        }
    }
}

fn normalize_key(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

pub(crate) fn resolve_config_path(config_path: &Path, value: &str) -> PathBuf {
    let cleaned = strip_quotes(value.trim()).replace("%SystemDrive%", "C:");
    let path = PathBuf::from(&cleaned);
    if path.is_absolute() {
        path
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(path)
    }
}

pub(crate) fn strip_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}
