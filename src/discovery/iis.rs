use std::path::{Path, PathBuf};

use crate::model::MiddlewareKind;

use super::{resolve_config_path, strip_quotes, DiscoveryBuilder};

pub fn add_standard_paths(builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Iis,
        "standard",
        25,
        "standard IIS paths considered",
    );
    builder.web_root(
        PathBuf::from(r"C:\inetpub\wwwroot"),
        "standard",
        Some("iis"),
        80,
        "standard IIS web root",
        "standard",
    );
    builder.log_path(
        PathBuf::from(r"C:\inetpub\logs\LogFiles"),
        "standard",
        Some("iis"),
        80,
        "standard IIS W3C log path",
        "standard",
    );
}

pub fn discover_from_config(content: &str, config_path: &Path, builder: &mut DiscoveryBuilder) {
    builder.middleware(
        MiddlewareKind::Iis,
        format!("config:{}", config_path.display()),
        80,
        "readable IIS applicationHost.config",
    );

    for value in find_attribute_values(content, "physicalPath") {
        builder.web_root(
            resolve_config_path(config_path, &value),
            format!("config:{}", config_path.display()),
            Some("iis"),
            30,
            "physicalPath attribute",
            "config",
        );
    }
    for value in find_attribute_values(content, "directory") {
        if value.to_ascii_lowercase().contains("log") {
            builder.log_path(
                resolve_config_path(config_path, &value),
                format!("config:{}", config_path.display()),
                Some("iis"),
                30,
                "logFile directory attribute",
                "config",
            );
        }
    }
}

fn find_attribute_values(content: &str, attr: &str) -> Vec<String> {
    let mut values = Vec::new();
    let needle = format!("{attr}=");
    for line in content.lines() {
        let mut rest = line;
        while let Some(index) = rest.find(&needle) {
            let after = &rest[index + needle.len()..];
            let delimiter = after.chars().next().unwrap_or('"');
            let after = after.trim_start_matches(delimiter);
            if let Some(value) = after.split(delimiter).next() {
                let value = strip_quotes(value);
                if !value.is_empty() {
                    values.push(value.to_string());
                }
            }
            rest = after;
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryBuilder;

    #[test]
    fn parses_iis_physical_path_and_log_directory() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_config(
            r#"
            <virtualDirectory path="/" physicalPath="C:\inetpub\site1" />
            <logFile directory="%SystemDrive%\inetpub\logs\LogFiles" />
            "#,
            Path::new(r"C:\Windows\System32\inetsrv\config\applicationHost.config"),
            &mut builder,
        );
        let result = builder.finish();

        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path.contains(r"C:\inetpub\site1")));
        assert!(result
            .logs
            .iter()
            .any(|row| row.path.contains(r"C:\inetpub\logs\LogFiles")));
    }
}
