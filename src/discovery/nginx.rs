use std::path::{Path, PathBuf};

use crate::model::MiddlewareKind;

use super::{resolve_config_path, strip_quotes, DiscoveryBuilder};

pub fn add_standard_paths(builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Nginx,
        "standard",
        25,
        "standard Nginx paths considered",
    );
    for path in standard_web_roots() {
        builder.web_root(
            path,
            "standard",
            Some("nginx"),
            80,
            "standard nginx web root",
            "standard",
        );
    }
    for path in standard_log_paths() {
        builder.log_path(
            path,
            "standard",
            Some("nginx"),
            80,
            "standard nginx log path",
            "standard",
        );
    }
}

pub fn discover_from_config(content: &str, config_path: &Path, builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Nginx,
        format!("config:{}", config_path.display()),
        80,
        "readable nginx config",
    );

    for line in content.lines().map(strip_comment).map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if let Some(value) = directive_value(line, "root") {
            builder.web_root(
                resolve_config_path(config_path, value),
                format!("config:{}", config_path.display()),
                Some("nginx"),
                30,
                "root directive",
                "config",
            );
        }
        // location 块里的 alias 同样指向真实文件系统目录,作为路径线索列出。
        if let Some(value) = directive_value(line, "alias") {
            builder.web_root(
                resolve_config_path(config_path, value),
                format!("config:{}", config_path.display()),
                Some("nginx"),
                35,
                "alias directive",
                "config",
            );
        }
        for directive in ["access_log", "error_log"] {
            if let Some(value) = directive_value(line, directive) {
                if value.eq_ignore_ascii_case("off") {
                    continue;
                }
                builder.log_path(
                    resolve_config_path(config_path, value),
                    format!("config:{}", config_path.display()),
                    Some("nginx"),
                    30,
                    format!("{directive} directive"),
                    "config",
                );
            }
        }
    }
}

fn directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    // 指令可出现在行内任意 token 位置(location 块单行写法 "location /x { alias /y; }"),
    // 但必须落在 token 边界上:裸子串会把 "rootdir /x" 误当 "root" 指令。
    let mut search_from = 0usize;
    while let Some(offset) = line[search_from..].find(directive) {
        let start = search_from + offset;
        let before_is_boundary = start == 0
            || line[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_whitespace() || ch == '{' || ch == ';');
        let after = &line[start + directive.len()..];
        if before_is_boundary && (after.starts_with(' ') || after.starts_with('\t')) {
            if let Some(first) = after.trim().split_whitespace().next() {
                return Some(strip_quotes(first.trim_end_matches(';')));
            }
        }
        search_from = start + directive.len();
    }
    None
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

#[cfg(windows)]
fn standard_web_roots() -> Vec<PathBuf> {
    vec![PathBuf::from(r"C:\nginx\html")]
}

#[cfg(unix)]
fn standard_web_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/share/nginx/html"),
        PathBuf::from("/var/www/html"),
    ]
}

#[cfg(windows)]
fn standard_log_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(r"C:\nginx\logs")]
}

#[cfg(unix)]
fn standard_log_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("/var/log/nginx")]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryBuilder;

    #[test]
    fn parses_nginx_root_and_logs() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            r#"
            server {
              root /srv/app/public;
              access_log /var/log/nginx/app_access.log combined;
              error_log "/var/log/nginx/app_error.log";
            }
            "#,
            Path::new("/etc/nginx/sites-enabled/app.conf"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path == "/srv/app/public"));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path == "/var/log/nginx/app_access.log"));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path == "/var/log/nginx/app_error.log"));
    }

    #[test]
    fn parses_alias_directive_and_rejects_prefix_lookalikes() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            r#"
            location /static/ { alias /srv/app/static; }
            rootdir /this/is/not/root;
            "#,
            Path::new("/etc/nginx/nginx.conf"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path == "/srv/app/static" && row.evidence == "alias directive"));
        // "rootdir" 不再被当成 "root" 指令误匹配。
        assert!(!result
            .web_roots
            .iter()
            .any(|row| row.path == "/this/is/not/root"));
    }
}
