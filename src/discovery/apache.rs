use std::path::{Path, PathBuf};

use crate::model::MiddlewareKind;

use super::{resolve_config_path, strip_quotes, DiscoveryBuilder};

pub fn add_standard_paths(builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Apache,
        "standard",
        25,
        "standard Apache paths considered",
    );
    for path in standard_web_roots() {
        builder.web_root(
            path,
            "standard",
            Some("apache"),
            80,
            "standard apache web root",
            "standard",
        );
    }
    for path in standard_log_paths() {
        builder.log_path(
            path,
            "standard",
            Some("apache"),
            80,
            "standard apache log path",
            "standard",
        );
    }
}

pub fn discover_from_config(content: &str, config_path: &Path, builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Apache,
        format!("config:{}", config_path.display()),
        80,
        "readable apache config",
    );

    for line in content.lines().map(strip_comment).map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if let Some(value) = directive_value(line, "DocumentRoot") {
            builder.web_root(
                resolve_config_path(config_path, value),
                format!("config:{}", config_path.display()),
                Some("apache"),
                30,
                "DocumentRoot directive",
                "config",
            );
        }
        for directive in ["CustomLog", "ErrorLog", "TransferLog"] {
            if let Some(value) = directive_value(line, directive) {
                builder.log_path(
                    resolve_config_path(config_path, value),
                    format!("config:{}", config_path.display()),
                    Some("apache"),
                    30,
                    format!("{directive} directive"),
                    "config",
                );
            }
        }
    }
}

fn directive_value<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case(directive) {
        return None;
    }
    parts.next().map(strip_quotes)
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

#[cfg(windows)]
fn standard_web_roots() -> Vec<PathBuf> {
    vec![PathBuf::from(r"C:\Apache24\htdocs")]
}

#[cfg(unix)]
fn standard_web_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/var/www/html"), PathBuf::from("/srv/www")]
}

#[cfg(windows)]
fn standard_log_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(r"C:\Apache24\logs")]
}

#[cfg(unix)]
fn standard_log_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/log/apache2"),
        PathBuf::from("/var/log/httpd"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryBuilder;

    #[test]
    fn parses_apache_document_root_and_logs() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            r#"
            DocumentRoot "/srv/http/public"
            CustomLog /var/log/apache2/access.log combined
            ErrorLog "/var/log/apache2/error.log"
            "#,
            Path::new("/etc/apache2/sites-enabled/app.conf"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path == "/srv/http/public"));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path == "/var/log/apache2/access.log"));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path == "/var/log/apache2/error.log"));
    }

    #[test]
    fn parses_transfer_log_directive() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            "TransferLog /var/log/httpd/transfer.log\n",
            Path::new("/etc/httpd/conf/httpd.conf"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .logs
            .iter()
            .any(|row| row.path == "/var/log/httpd/transfer.log"
                && row.evidence == "TransferLog directive"));
    }
}
