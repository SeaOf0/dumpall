use std::path::{Path, PathBuf};

use crate::model::MiddlewareKind;

use super::{strip_quotes, DiscoveryBuilder};

pub fn add_standard_paths(builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Tomcat,
        "standard",
        25,
        "standard Tomcat paths considered",
    );
    for path in standard_web_roots() {
        builder.web_root(
            path,
            "standard",
            Some("tomcat"),
            80,
            "standard tomcat webapps path",
            "standard",
        );
    }
    for path in standard_log_paths() {
        builder.log_path(
            path,
            "standard",
            Some("tomcat"),
            80,
            "standard tomcat log path",
            "standard",
        );
    }
}

pub fn discover_from_config(content: &str, config_path: &Path, builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Tomcat,
        format!("config:{}", config_path.display()),
        80,
        "readable tomcat server.xml",
    );

    let base = catalina_base_from_config_path(config_path);
    builder.log_path(
        base.join("logs"),
        format!("config:{}", config_path.display()),
        Some("tomcat"),
        35,
        "CATALINA_BASE logs",
        "config",
    );

    for app_base in parse_app_bases(content) {
        let path = if Path::new(&app_base).is_absolute() {
            PathBuf::from(app_base)
        } else {
            base.join(app_base)
        };
        builder.web_root(
            path,
            format!("config:{}", config_path.display()),
            Some("tomcat"),
            35,
            "Host appBase",
            "config",
        );
    }
}

pub fn add_catalina_base(base: PathBuf, source: impl Into<String>, builder: &mut DiscoveryBuilder) {
    let source = source.into();
    builder.middleware(
        MiddlewareKind::Tomcat,
        source.clone(),
        70,
        "catalina base in process command line",
    );
    builder.log_path(
        base.join("logs"),
        source.clone(),
        Some("tomcat"),
        25,
        "catalina base logs",
        "process",
    );
    builder.web_root(
        base.join("webapps"),
        source,
        Some("tomcat"),
        25,
        "catalina base webapps",
        "process",
    );
}

fn catalina_base_from_config_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf()
}

fn parse_app_bases(content: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(index) = lower.find("appbase=") else {
            continue;
        };
        let raw = &line[index + "appBase=".len()..];
        let delimiter = raw.chars().next().unwrap_or('"');
        let raw = raw.trim_start_matches(delimiter);
        let value = raw
            .split(delimiter)
            .next()
            .map(strip_quotes)
            .unwrap_or_default();
        if !value.is_empty() {
            values.push(value.to_string());
        }
    }
    if values.is_empty() {
        values.push("webapps".to_string());
    }
    values
}

#[cfg(windows)]
fn standard_web_roots() -> Vec<PathBuf> {
    tomcat_base_dirs()
        .into_iter()
        .map(|dir| dir.join("webapps"))
        .collect()
}

#[cfg(windows)]
fn standard_log_paths() -> Vec<PathBuf> {
    tomcat_base_dirs()
        .into_iter()
        .map(|dir| dir.join("logs"))
        .collect()
}

/// Windows 常见 Tomcat 根目录:Program Files 下的 8.5/9/10/11 各版本目录,
/// 加上 %CATALINA_HOME% 环境变量指定的安装位置(设置时优先级同样作为线索)。
#[cfg(windows)]
fn tomcat_base_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for version in ["8.5", "9.0", "10.0", "10.1", "11.0"] {
        dirs.push(PathBuf::from(format!(
            r"C:\Program Files\Apache Software Foundation\Tomcat {version}"
        )));
    }
    if let Ok(home) = std::env::var("CATALINA_HOME") {
        let home = home.trim();
        if !home.is_empty() {
            dirs.push(PathBuf::from(home));
        }
    }
    dirs
}

#[cfg(unix)]
fn standard_web_roots() -> Vec<PathBuf> {
    tomcat_base_dirs()
        .into_iter()
        .map(|dir| dir.join("webapps"))
        .collect()
}

#[cfg(unix)]
fn standard_log_paths() -> Vec<PathBuf> {
    let mut paths = tomcat_base_dirs()
        .into_iter()
        .map(|dir| dir.join("logs"))
        .collect::<Vec<_>>();
    paths.push(PathBuf::from("/var/log/tomcat"));
    paths
}

/// unix 常见 Tomcat 根目录:/opt/tomcat 加上发行版包管理器与手工解包的
/// 版本化目录(/usr/share/tomcat*、/var/lib/tomcat*、/opt/apache-tomcat-*),
/// 通过 read_dir 前缀匹配展开。
#[cfg(unix)]
fn tomcat_base_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/opt/tomcat")];
    for (parent, prefix) in [
        ("/usr/share", "tomcat"),
        ("/var/lib", "tomcat"),
        ("/opt", "apache-tomcat-"),
    ] {
        let Ok(entries) = std::fs::read_dir(parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with(prefix) {
                dirs.push(entry.path());
            }
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryBuilder;

    #[test]
    fn parses_tomcat_app_base() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            r#"<Host name="localhost" appBase="apps" unpackWARs="true" />"#,
            Path::new("/opt/tomcat/conf/server.xml"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path.replace('\\', "/").ends_with("/opt/tomcat/apps")));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path.replace('\\', "/").ends_with("/opt/tomcat/logs")));
    }

    #[test]
    #[cfg(unix)]
    fn standard_paths_cover_versioned_tomcat_directories() {
        // /opt/tomcat 恒在;版本化目录(/usr/share/tomcat* 等)依赖宿主机
        // 是否存在,由 read_dir 枚举,不在此断言具体命中。
        let roots = standard_web_roots();
        let logs = standard_log_paths();
        assert!(roots.iter().any(|path| path.ends_with("opt/tomcat/webapps")));
        assert!(logs.iter().any(|path| path.ends_with("var/log/tomcat")));
    }
}
