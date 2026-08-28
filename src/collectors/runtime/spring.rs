use std::fs;
use std::path::Path;

use regex::Regex;

use crate::config::ResolvedRun;
use crate::model::CollectionError;

use super::{
    artifact_metadata, component_id, confidence_for_flags, display_path, extension,
    is_broad_mapping, join_flags, push_java_artifact, push_java_virtual_artifact, push_warning,
    record_seen_file, suspicious_component_name, RuntimeInventory, SpringMappingRow,
};

pub const COLLECTOR_SCOPE: &str = "spring_mappings";

pub(crate) fn collect_spring_app_path(
    resolved: &ResolvedRun,
    app_path: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    if !app_path.exists() {
        push_warning(
            inventory,
            errors,
            "spring",
            app_path,
            "discover",
            "Spring application path does not exist",
            Some("Provide a readable Spring Boot jar or application directory.".to_string()),
        );
        return Ok(());
    }

    if app_path.is_file() {
        collect_spring_file(resolved, app_path, inventory, errors)?;
    } else if app_path.is_dir() {
        collect_spring_directory(resolved, app_path, inventory, errors)?;
    }
    Ok(())
}

pub(crate) fn collect_spring_log_mappings(
    resolved: &ResolvedRun,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    for path in &resolved.app_log_paths {
        if !path.exists() {
            continue;
        }
        if path.is_file() {
            parse_log_file(resolved, path, inventory, errors)?;
        } else if path.is_dir() {
            for file in super::walk_files(path, resolved.safety.max_depth) {
                parse_log_file(resolved, &file, inventory, errors)?;
            }
        }
    }
    Ok(())
}

fn collect_spring_file(
    resolved: &ResolvedRun,
    app_path: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let ext = extension(app_path);
    if matches!(ext.as_str(), "jar" | "war" | "zip") {
        collect_archive_summary(resolved, app_path, inventory, errors)?;
    } else if matches!(ext.as_str(), "properties" | "yml" | "yaml") {
        collect_config_file(resolved, app_path, app_path, inventory, errors)?;
    }
    Ok(())
}

fn collect_spring_directory(
    resolved: &ResolvedRun,
    app_dir: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    for file in super::walk_files(app_dir, resolved.safety.max_depth) {
        match extension(&file).as_str() {
            "jar" | "war" | "zip" => {
                if file.components().any(|part| {
                    part.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("BOOT-INF")
                }) {
                    push_java_artifact(
                        inventory,
                        resolved,
                        "spring",
                        "jar",
                        file.file_name()
                            .and_then(|value| value.to_str())
                            .unwrap_or("library.jar"),
                        "",
                        &file,
                        display_path(&file),
                        "BOOT-INF/lib",
                        &["static_archive_component"],
                    );
                } else {
                    collect_archive_summary(resolved, &file, inventory, errors)?;
                }
            }
            "class" => collect_class_file(resolved, &file, app_dir, inventory),
            "properties" | "yml" | "yaml" => {
                collect_config_file(resolved, &file, app_dir, inventory, errors)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// 单个 Spring 归档（jar/war/zip）的读取上限：归档内容按文本扫描 entry 名与
/// mapping 字面量，超过 64MB 截断读取并登记错误，防止 GB 级 fat jar 拖垮内存。
const MAX_SPRING_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// 应用日志流式解析的单行上限（与 parsers 一致：1MB/行）。
const MAX_SPRING_LOG_LINE_BYTES: usize = 1024 * 1024;

fn collect_archive_summary(
    resolved: &ResolvedRun,
    archive_path: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    // metadata 预检在读盘前完成：超限文件截断到 64MB 并显式登记，不静默吞掉。
    let file_size = fs::metadata(archive_path).map(|metadata| metadata.len()).unwrap_or(0);
    let truncated = file_size > MAX_SPRING_ARCHIVE_BYTES;
    let bytes = match read_archive_prefix(archive_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_warning(
                inventory,
                errors,
                "spring",
                archive_path,
                "read_file",
                "Spring archive could not be read",
                Some(error.to_string()),
            );
            return Ok(());
        }
    };
    if truncated {
        push_warning(
            inventory,
            errors,
            "spring",
            archive_path,
            "preflight",
            "Spring archive exceeds the 64MB single-file scan cap; only the first 64MB was inspected",
            Some(format!(
                "file size: {file_size} bytes, cap: {MAX_SPRING_ARCHIVE_BYTES} bytes"
            )),
        );
    }
    let text = String::from_utf8_lossy(&bytes);
    let metadata = artifact_metadata(resolved, archive_path, resolved.safety.max_file_size_mb);
    let archive_name = archive_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("spring-application.jar");

    push_java_artifact(
        inventory,
        resolved,
        "spring",
        "jar",
        archive_name,
        "",
        archive_path,
        archive_path.display().to_string(),
        "spring_app_path",
        &["static_archive_component"],
    );

    for entry in extract_zip_like_entry_names(&text) {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("boot-inf/lib/") && lower.ends_with(".jar") {
            push_java_virtual_artifact(
                inventory,
                "spring",
                "jar",
                Path::new(&entry)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(entry.as_str()),
                "",
                archive_path.display().to_string(),
                entry.clone(),
                "BOOT-INF/lib",
                metadata.mtime.clone(),
                metadata.sha256.clone(),
                metadata.is_recent,
                &["static_archive_component"],
            );
        } else if lower.starts_with("boot-inf/classes/") && lower.ends_with(".class") {
            push_spring_mapping(
                inventory,
                "class",
                "",
                "",
                class_name_from_archive_entry(&entry),
                archive_path.display().to_string(),
                "static_archive",
                false,
                false,
                true,
                metadata.mtime.clone(),
                metadata.sha256.clone(),
                &["static_archive_component"],
            );
        } else if lower.contains("application.properties")
            || lower.contains("application.yml")
            || lower.contains("application.yaml")
        {
            let flags = config_flags_from_text(&text);
            push_spring_mapping(
                inventory,
                "config",
                "",
                "",
                Path::new(&entry)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("application-config"),
                archive_path.display().to_string(),
                "static_archive",
                false,
                false,
                true,
                metadata.mtime.clone(),
                metadata.sha256.clone(),
                &flags,
            );
        }
    }

    extract_mapping_literals(&text)
        .into_iter()
        .for_each(|mapping| {
            push_spring_mapping(
                inventory,
                "controller",
                mapping.route,
                mapping.method,
                mapping.class_name,
                archive_path.display().to_string(),
                "static_archive",
                false,
                false,
                true,
                metadata.mtime.clone(),
                metadata.sha256.clone(),
                &["static_archive_component"],
            )
        });
    Ok(())
}

fn collect_class_file(
    resolved: &ResolvedRun,
    file: &Path,
    app_dir: &Path,
    inventory: &mut RuntimeInventory,
) {
    let metadata = artifact_metadata(resolved, file, resolved.safety.max_file_size_mb);
    let class_name = class_name_from_path(file, app_dir);
    push_spring_mapping(
        inventory,
        "class",
        "",
        "",
        class_name,
        file.display().to_string(),
        "static_directory",
        false,
        false,
        true,
        metadata.mtime,
        metadata.sha256,
        &["static_archive_component"],
    );
}

fn collect_config_file(
    resolved: &ResolvedRun,
    config_path: &Path,
    root: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let content = match fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(error) => {
            push_warning(
                inventory,
                errors,
                "spring",
                config_path,
                "read_file",
                "Spring config file could not be read",
                Some(error.to_string()),
            );
            return Ok(());
        }
    };
    let metadata = artifact_metadata(resolved, config_path, resolved.safety.max_file_size_mb);
    let flags = config_flags_from_text(&content);
    push_spring_mapping(
        inventory,
        "config",
        "",
        "",
        config_path
            .strip_prefix(root)
            .unwrap_or(config_path)
            .display()
            .to_string(),
        config_path.display().to_string(),
        "config_file",
        false,
        false,
        true,
        metadata.mtime,
        metadata.sha256,
        &flags,
    );
    Ok(())
}

fn parse_log_file(
    resolved: &ResolvedRun,
    path: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    // 读前闸门：超 max_file_size_mb 的日志跳过（与其余采集器语义一致）。
    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    if let Ok(metadata) = fs::metadata(path) {
        if metadata.len() > max_bytes {
            push_warning(
                inventory,
                errors,
                "spring",
                path,
                "preflight",
                "application log exceeds max-file-size limit and was skipped for Spring mapping hints",
                Some(format!(
                    "{} bytes (limit {} bytes)",
                    metadata.len(),
                    max_bytes
                )),
            );
            return Ok(());
        }
    }
    let Ok(file) = fs::File::open(path) else {
        push_warning(
            inventory,
            errors,
            "spring",
            path,
            "read_file",
            "Application log could not be read for Spring mapping hints",
            None,
        );
        return Ok(());
    };
    let metadata = artifact_metadata(resolved, path, resolved.safety.max_file_size_mb);
    // 流式逐行（read_until + lossy）：日志可以是 GB 级 append-only 文件，
    // 不再 read_to_string 整读；单行超 1MB 时截断参与匹配（与 parsers 一致）。
    let mut reader = std::io::BufReader::new(file);
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    while let Some(line) = crate::parsers::read_decoded_log_line(&mut reader, &mut buffer)? {
        let text = if line.byte_len > MAX_SPRING_LOG_LINE_BYTES {
            safe_prefix(&line.text, MAX_SPRING_LOG_LINE_BYTES)
        } else {
            line.text.as_str()
        };
        for mapping in extract_log_mappings(text) {
            push_spring_mapping(
                inventory,
                "controller",
                mapping.route,
                mapping.method,
                mapping.class_name,
                path.display().to_string(),
                "application_log",
                false,
                true,
                false,
                metadata.mtime.clone(),
                metadata.sha256.clone(),
                &["log_mapping_hint"],
            );
        }
    }
    Ok(())
}

/// 读取归档前 MAX_SPRING_ARCHIVE_BYTES 字节（take 截断）。
fn read_archive_prefix(archive_path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(archive_path)?;
    let mut limited = file.take(MAX_SPRING_ARCHIVE_BYTES);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// 按字节上限截断字符串（退避到字符边界；与 parsers::safe_prefix 同语义）。
fn safe_prefix(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[allow(clippy::too_many_arguments)]
fn push_spring_mapping(
    inventory: &mut RuntimeInventory,
    component_type: impl Into<String>,
    route: impl Into<String>,
    http_method: impl Into<String>,
    class_name: impl Into<String>,
    jar_path: impl Into<String>,
    source: impl Into<String>,
    is_from_actuator: bool,
    is_from_log: bool,
    is_from_static_archive: bool,
    mtime: impl Into<String>,
    sha256: impl Into<String>,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let component_type = component_type.into();
    let route = route.into();
    let http_method = http_method.into();
    let class_name = class_name.into();
    let jar_path = jar_path.into();
    let source = source.into();
    let mtime = mtime.into();
    let sha256 = sha256.into();
    let mut flags = extra_flags.to_vec();
    if is_broad_mapping(&route) {
        flags.push("broad_mapping");
    }
    if suspicious_component_name(&route) || suspicious_component_name(&class_name) {
        flags.push("suspicious_name");
    }
    if route.contains("/actuator") || route.contains("/env") || route.contains("/heapdump") {
        flags.push("management_endpoint_exposure");
    }
    let risk_flags = join_flags(flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        "spring",
        &component_type,
        &route,
        &http_method,
        &class_name,
        &jar_path,
        &sha256,
    ]);
    inventory.spring_mappings.push(SpringMappingRow {
        component_id,
        component_type,
        route,
        http_method,
        class_name,
        jar_path,
        source,
        is_from_actuator,
        is_from_log,
        is_from_static_archive,
        mtime,
        sha256,
        risk_flags,
        confidence,
    });
}

#[derive(Debug)]
struct MappingHint {
    route: String,
    method: String,
    class_name: String,
}

fn extract_log_mappings(content: &str) -> Vec<MappingHint> {
    let mut hints = Vec::new();
    let Ok(regex) = Regex::new(
        r#"(?i)(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\s*(?:\{|\[)?\s*(/[A-Za-z0-9_./*{}-]+)\s*(?:\}|\])?.{0,160}?([A-Za-z_$][A-Za-z0-9_$.]+(?:Controller|Handler|Interceptor|Filter))"#,
    ) else {
        return hints;
    };
    for captures in regex.captures_iter(content) {
        hints.push(MappingHint {
            route: captures
                .get(2)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
            method: captures
                .get(1)
                .map(|value| value.as_str().to_ascii_uppercase())
                .unwrap_or_default(),
            class_name: captures
                .get(3)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
        });
    }
    hints
}

fn extract_mapping_literals(content: &str) -> Vec<MappingHint> {
    let mut hints = Vec::new();
    let text = content.replace('\0', " ");
    let Ok(regex) = Regex::new(
        r#"(?i)(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping).{0,80}?(/[A-Za-z0-9_./*{}-]+)"#,
    ) else {
        return hints;
    };
    for captures in regex.captures_iter(&text) {
        let annotation = captures.get(1).map(|value| value.as_str()).unwrap_or("");
        hints.push(MappingHint {
            route: captures
                .get(2)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
            method: method_from_annotation(annotation),
            class_name: String::new(),
        });
    }
    hints
}

fn method_from_annotation(annotation: &str) -> String {
    match annotation.to_ascii_lowercase().as_str() {
        "getmapping" => "GET",
        "postmapping" => "POST",
        "putmapping" => "PUT",
        "deletemapping" => "DELETE",
        "patchmapping" => "PATCH",
        _ => "",
    }
    .to_string()
}

fn extract_zip_like_entry_names(text: &str) -> Vec<String> {
    let Ok(regex) = Regex::new(
        r#"(?i)(BOOT-INF/(?:classes|lib)/[A-Za-z0-9_./$@()+ -]+\.(?:class|jar|properties|ya?ml))"#,
    ) else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_string()))
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn config_flags_from_text(content: &str) -> Vec<&'static str> {
    let lower = content.to_ascii_lowercase();
    let mut flags = Vec::new();
    if lower.contains("management.endpoints.web.exposure.include=*")
        || lower.contains("management:\n")
        || lower.contains("heapdump")
        || lower.contains("env:")
    {
        flags.push("management_endpoint_exposure");
    }
    if lower.contains("spring.main.allow-circular-references=true")
        || lower.contains("spring.mvc.hiddenmethod.filter.enabled=true")
    {
        flags.push("unusual_runtime_config");
    }
    flags
}

fn class_name_from_archive_entry(entry: &str) -> String {
    entry
        .trim_start_matches("BOOT-INF/classes/")
        .trim_end_matches(".class")
        .replace(['/', '$'], ".")
}

fn class_name_from_path(file: &Path, root: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .with_extension("")
        .display()
        .to_string()
        .replace(['\\', '/', '$'], ".")
}
