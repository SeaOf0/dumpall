use std::path::PathBuf;

use crate::model::MiddlewareKind;

use super::tomcat;
use super::DiscoveryBuilder;

pub fn discover_from_process_text(process_text: &str, builder: &mut DiscoveryBuilder) {
    if discover_from_process_csv(process_text, builder) {
        return;
    }

    for line in process_text.lines() {
        analyze_process_line(line, line, line, line, builder);
    }
}

fn discover_from_process_csv(process_text: &str, builder: &mut DiscoveryBuilder) -> bool {
    let mut reader = csv::Reader::from_reader(process_text.as_bytes());
    let Ok(headers) = reader.headers().cloned() else {
        return false;
    };

    let name_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("name"));
    let exe_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("executable_path"));
    let command_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("command_line"));

    if name_index.is_none() && exe_index.is_none() && command_index.is_none() {
        return false;
    }

    for record in reader.records().flatten() {
        let name = name_index.and_then(|index| record.get(index)).unwrap_or("");
        let exe = exe_index.and_then(|index| record.get(index)).unwrap_or("");
        let command = command_index
            .and_then(|index| record.get(index))
            .unwrap_or("");
        let evidence = record.iter().collect::<Vec<_>>().join(",");
        analyze_process_line(name, exe, command, &evidence, builder);
    }
    true
}

fn analyze_process_line(
    name: &str,
    executable_path: &str,
    command_line: &str,
    evidence: &str,
    builder: &mut DiscoveryBuilder,
) {
    if is_collector_command(command_line) {
        return;
    }

    let binary = format!("{name} {executable_path}").to_ascii_lowercase();
    let command = command_line.to_ascii_lowercase();

    if binary.contains("nginx") {
        builder.middleware(MiddlewareKind::Nginx, "process", 55, line_summary(evidence));
        super::nginx::add_standard_paths(builder);
        if let Some(prefix) = executable_parent(executable_path, "nginx") {
            builder.log_path(
                prefix.join("logs"),
                "process",
                Some("nginx"),
                45,
                "nginx executable parent logs",
                "process",
            );
            builder.web_root(
                prefix.join("html"),
                "process",
                Some("nginx"),
                45,
                "nginx executable parent html",
                "process",
            );
        }
    }
    if binary.contains("apache") || binary.contains("httpd") {
        builder.middleware(
            MiddlewareKind::Apache,
            "process",
            55,
            line_summary(evidence),
        );
        super::apache::add_standard_paths(builder);
    }
    if binary.contains("tomcat") || command.contains("tomcat") || command.contains("catalina") {
        builder.middleware(
            MiddlewareKind::Tomcat,
            "process",
            55,
            line_summary(evidence),
        );
        super::tomcat::add_standard_paths(builder);
        if let Some(base) = extract_dash_d_path(command_line, "catalina.base")
            .or_else(|| extract_dash_d_path(command_line, "catalina.home"))
        {
            tomcat::add_catalina_base(base, "process", builder);
        }
    }
    if binary.contains("w3wp.exe") {
        builder.middleware(MiddlewareKind::Iis, "process", 55, line_summary(evidence));
        super::iis::add_standard_paths(builder);
    }
}

fn is_collector_command(command_line: &str) -> bool {
    let lower = command_line.to_ascii_lowercase();
    lower.contains("$webnames")
        || lower.contains("get-ciminstance win32_process")
        || lower.contains("convertto-csv")
}

fn extract_dash_d_path(line: &str, key: &str) -> Option<PathBuf> {
    let needle = format!("-D{key}=");
    let index = line.find(&needle)?;
    let value = &line[index + needle.len()..];
    let value = value
        .split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'')
        .next()
        .unwrap_or_default();
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn executable_parent(line: &str, needle: &str) -> Option<PathBuf> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(needle)?;
    let before = &line[..index + needle.len()];
    let start = before
        .rfind(|ch: char| ch == '"' || ch == ',' || ch.is_whitespace())
        .map(|pos| pos + 1)
        .unwrap_or(0);
    let candidate = before[start..].trim_matches('"');
    let path = PathBuf::from(candidate);
    path.parent().map(PathBuf::from)
}

fn line_summary(line: &str) -> String {
    const MAX: usize = 160;
    if line.len() <= MAX {
        line.to_string()
    } else {
        // MAX 是字节长度,可能落在多字节字符(中文命令行)中间;
        // 回退到最近的字符边界再截取,避免字节切片 panic。
        let mut end = MAX;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &line[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryBuilder;

    #[test]
    fn discovers_tomcat_from_catalina_base() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_process_text(
            r#"java.exe -Dcatalina.base=C:\Tomcat9 -jar bootstrap.jar"#,
            &mut builder,
        );
        let result = builder.finish();

        assert!(result.logs.iter().any(|row| row.path.contains("Tomcat9")));
        assert!(result
            .web_roots
            .iter()
            .any(|row| row.path.contains("webapps")));
    }

    #[test]
    fn ignores_collector_script_keyword_lists() {
        let mut builder = DiscoveryBuilder::default();
        discover_from_process_text(
            r#""pid","name","executable_path","command_line"
"1","powershell.exe","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","$webNames = @('nginx','apache','tomcat'); Get-CimInstance Win32_Process | ConvertTo-Csv"
"#,
            &mut builder,
        );
        let result = builder.finish();

        assert!(result.middleware.is_empty());
        assert!(result.web_roots.is_empty());
        assert!(result.logs.is_empty());
    }

    #[test]
    fn truncates_long_multibyte_line_without_panic() {
        // 中文命令行超过 160 字节时,截断点必须落在字符边界上,不能 panic。
        let long_line = format!("nginx worker {}", "中文命令行参数".repeat(60));
        assert!(long_line.len() > 160);
        let summary = line_summary(&long_line);
        assert!(summary.ends_with("..."));
        assert!(summary.len() < long_line.len());

        let mut builder = DiscoveryBuilder::default();
        discover_from_process_text(&long_line, &mut builder);
        assert!(builder
            .finish()
            .middleware
            .iter()
            .any(|row| row.kind == "nginx"));
    }
}
