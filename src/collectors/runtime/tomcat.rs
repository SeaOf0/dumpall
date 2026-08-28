use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::config::ResolvedRun;
use crate::model::CollectionError;

use super::{
    component_id, confidence_for_flags, display_path, extension, is_broad_mapping, join_flags,
    push_java_artifact, push_warning, record_seen_file, suspicious_component_name, tag_blocks,
    tag_starts, text_between_tags, xml_attr, RuntimeInventory, TomcatComponentRow,
};

pub const COLLECTOR_SCOPE: &str = "tomcat_components";

pub(crate) fn collect_tomcat_base(
    resolved: &ResolvedRun,
    tomcat_base: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    if !tomcat_base.exists() {
        push_warning(
            inventory,
            errors,
            "tomcat",
            tomcat_base,
            "discover",
            "Tomcat base path does not exist",
            Some(
                "Provide a readable --tomcat-base path or an offline copy of CATALINA_BASE."
                    .to_string(),
            ),
        );
        return Ok(());
    }
    if !tomcat_base.is_dir() {
        push_warning(
            inventory,
            errors,
            "tomcat",
            tomcat_base,
            "discover",
            "Tomcat base path is not a directory",
            Some("Tomcat collection expects a CATALINA_BASE-style directory.".to_string()),
        );
        return Ok(());
    }

    collect_conf_xml(resolved, tomcat_base, inventory, errors)?;
    collect_webapps(resolved, tomcat_base, inventory, errors)?;
    collect_tomcat_artifacts(resolved, tomcat_base, inventory, errors)?;
    Ok(())
}

fn collect_conf_xml(
    resolved: &ResolvedRun,
    tomcat_base: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    for relative in ["conf/server.xml", "conf/context.xml", "conf/web.xml"] {
        let path = tomcat_base.join(relative);
        if !path.exists() {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) => {
                push_warning(
                    inventory,
                    errors,
                    "tomcat",
                    &path,
                    "read_file",
                    "Tomcat XML file could not be read",
                    Some(error.to_string()),
                );
                continue;
            }
        };
        parse_tomcat_xml(resolved, &path, relative, &content, inventory);
    }
    Ok(())
}

fn collect_webapps(
    resolved: &ResolvedRun,
    tomcat_base: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let webapps = tomcat_base.join("webapps");
    if !webapps.is_dir() {
        return Ok(());
    }
    let entries = match fs::read_dir(&webapps) {
        Ok(entries) => entries,
        Err(error) => {
            push_warning(
                inventory,
                errors,
                "tomcat",
                &webapps,
                "read_dir",
                "Tomcat webapps directory could not be read",
                Some(error.to_string()),
            );
            return Ok(());
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_webapp_dir(resolved, &path, inventory, errors)?;
        } else if file_type.is_file() && extension(&path) == "war" {
            push_tomcat_file_component(
                resolved,
                inventory,
                "war",
                path.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("application.war"),
                "",
                "",
                &path,
                &path,
                "webapps",
                &["webapps_artifact"],
            );
        }
    }
    Ok(())
}

fn collect_webapp_dir(
    resolved: &ResolvedRun,
    app_dir: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let web_xml = app_dir.join("WEB-INF").join("web.xml");
    if web_xml.is_file() {
        match fs::read_to_string(&web_xml) {
            Ok(content) => {
                let declared = app_dir
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("webapp");
                parse_tomcat_xml(resolved, &web_xml, declared, &content, inventory);
            }
            Err(error) => push_warning(
                inventory,
                errors,
                "tomcat",
                &web_xml,
                "read_file",
                "Tomcat webapp web.xml could not be read",
                Some(error.to_string()),
            ),
        }
    }

    for file in super::walk_files(app_dir, resolved.safety.max_depth) {
        let ext = extension(&file);
        match ext.as_str() {
            "jar" => push_java_artifact(
                inventory,
                resolved,
                "tomcat",
                "jar",
                file.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("library.jar"),
                "",
                &file,
                display_path(&file),
                app_dir.display().to_string(),
                &["webapps_artifact"],
            ),
            "jsp" => push_tomcat_file_component(
                resolved,
                inventory,
                "jsp",
                file.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("page.jsp"),
                "",
                "",
                &file,
                &file,
                app_dir.display().to_string(),
                &["webapps_artifact"],
            ),
            "class" => push_tomcat_file_component(
                resolved,
                inventory,
                "class",
                file.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("component.class"),
                class_name_from_path(&file),
                "",
                &file,
                &file,
                app_dir.display().to_string(),
                &["webapps_artifact"],
            ),
            _ => {}
        }
    }
    Ok(())
}

fn collect_tomcat_artifacts(
    resolved: &ResolvedRun,
    tomcat_base: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    for relative in ["lib", "work", "temp"] {
        let dir = tomcat_base.join(relative);
        if !dir.is_dir() {
            continue;
        }
        let files = super::walk_files(&dir, resolved.safety.max_depth);
        for file in files {
            let ext = extension(&file);
            let flags = if matches!(relative, "work" | "temp") {
                vec!["work_temp_artifact"]
            } else {
                Vec::new()
            };
            match ext.as_str() {
                "jar" => push_java_artifact(
                    inventory,
                    resolved,
                    "tomcat",
                    "jar",
                    file.file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("library.jar"),
                    "",
                    &file,
                    display_path(&file),
                    relative,
                    &flags,
                ),
                "jsp" => push_tomcat_file_component(
                    resolved,
                    inventory,
                    "jsp",
                    file.file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("page.jsp"),
                    "",
                    "",
                    &file,
                    &file,
                    relative,
                    &flags,
                ),
                "class" => push_tomcat_file_component(
                    resolved,
                    inventory,
                    "class",
                    file.file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("component.class"),
                    class_name_from_path(&file),
                    "",
                    &file,
                    &file,
                    relative,
                    &flags,
                ),
                _ => {}
            }
        }
    }

    if inventory.files_seen >= super::MAX_RUNTIME_FILES_PER_RUN {
        push_warning(
            inventory,
            errors,
            "tomcat",
            tomcat_base,
            "scan_limit",
            "runtime file scan limit reached",
            Some(
                "The run stopped adding runtime artifacts after the configured internal limit."
                    .to_string(),
            ),
        );
    }
    Ok(())
}

fn parse_tomcat_xml(
    resolved: &ResolvedRun,
    source_file: &Path,
    declared_in: &str,
    xml: &str,
    inventory: &mut RuntimeInventory,
) {
    let mut filter_classes = BTreeMap::new();
    let mut servlet_classes = BTreeMap::new();

    for block in tag_blocks(xml, "filter") {
        let name = text_between_tags(block, "filter-name").unwrap_or_default();
        let class_name = text_between_tags(block, "filter-class").unwrap_or_default();
        filter_classes.insert(name.clone(), class_name.clone());
        push_tomcat_xml_component(
            resolved,
            inventory,
            "filter",
            &name,
            &class_name,
            "",
            source_file,
            declared_in,
        );
    }

    for block in tag_blocks(xml, "filter-mapping") {
        let name = text_between_tags(block, "filter-name").unwrap_or_default();
        let class_name = filter_classes.get(&name).cloned().unwrap_or_default();
        let patterns = tag_blocks(block, "url-pattern")
            .into_iter()
            .filter_map(|pattern| text_between_tags(pattern, "url-pattern"))
            .collect::<Vec<_>>();
        for pattern in patterns {
            push_tomcat_xml_component(
                resolved,
                inventory,
                "filter_mapping",
                &name,
                &class_name,
                &pattern,
                source_file,
                declared_in,
            );
        }
    }

    for block in tag_blocks(xml, "listener") {
        let class_name = text_between_tags(block, "listener-class").unwrap_or_default();
        let name = class_name
            .rsplit('.')
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("listener");
        push_tomcat_xml_component(
            resolved,
            inventory,
            "listener",
            name,
            &class_name,
            "",
            source_file,
            declared_in,
        );
    }

    for block in tag_blocks(xml, "servlet") {
        let name = text_between_tags(block, "servlet-name").unwrap_or_default();
        let class_name = text_between_tags(block, "servlet-class")
            .or_else(|| text_between_tags(block, "jsp-file"))
            .unwrap_or_default();
        servlet_classes.insert(name.clone(), class_name.clone());
        push_tomcat_xml_component(
            resolved,
            inventory,
            "servlet",
            &name,
            &class_name,
            "",
            source_file,
            declared_in,
        );
    }

    for block in tag_blocks(xml, "servlet-mapping") {
        let name = text_between_tags(block, "servlet-name").unwrap_or_default();
        let class_name = servlet_classes.get(&name).cloned().unwrap_or_default();
        let patterns = tag_blocks(block, "url-pattern")
            .into_iter()
            .filter_map(|pattern| text_between_tags(pattern, "url-pattern"))
            .collect::<Vec<_>>();
        for pattern in patterns {
            push_tomcat_xml_component(
                resolved,
                inventory,
                "servlet_mapping",
                &name,
                &class_name,
                &pattern,
                source_file,
                declared_in,
            );
        }
    }

    for tag in tag_starts(xml, "Valve") {
        let class_name = xml_attr(tag, "className").unwrap_or_default();
        let name = xml_attr(tag, "name")
            .unwrap_or_else(|| class_name.rsplit('.').next().unwrap_or("valve").to_string());
        push_tomcat_xml_component(
            resolved,
            inventory,
            "valve",
            &name,
            &class_name,
            "",
            source_file,
            declared_in,
        );
    }

    for tag in tag_starts(xml, "Realm") {
        let class_name = xml_attr(tag, "className").unwrap_or_default();
        let name = xml_attr(tag, "name")
            .unwrap_or_else(|| class_name.rsplit('.').next().unwrap_or("realm").to_string());
        push_tomcat_xml_component(
            resolved,
            inventory,
            "realm",
            &name,
            &class_name,
            "",
            source_file,
            declared_in,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_tomcat_xml_component(
    resolved: &ResolvedRun,
    inventory: &mut RuntimeInventory,
    component_type: &str,
    name: &str,
    class_name: &str,
    url_pattern: &str,
    source_file: &Path,
    declared_in: &str,
) {
    let mut flags = Vec::new();
    // web.xml 会产出 filter/servlet/mapping 多行组件；同一文件按路径 memoize
    // 只读盘+哈希一次（走 RuntimeInventory::cached_artifact_metadata）。
    let metadata = inventory.cached_artifact_metadata(resolved, source_file);
    if metadata.is_recent {
        flags.push("recent_change");
    }
    if is_broad_mapping(url_pattern) {
        flags.push("broad_mapping");
    }
    if suspicious_component_name(name) {
        flags.push("suspicious_name");
    }
    if suspicious_component_name(class_name) {
        flags.push("suspicious_class");
    }
    let risk_flags = join_flags(flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        "tomcat",
        component_type,
        name,
        class_name,
        url_pattern,
        &source_file.display().to_string(),
        &metadata.sha256,
    ]);
    inventory.tomcat_components.push(TomcatComponentRow {
        component_id,
        runtime_type: "tomcat".to_string(),
        component_type: component_type.to_string(),
        name: name.to_string(),
        class_name: class_name.to_string(),
        url_pattern: url_pattern.to_string(),
        source_file: source_file.display().to_string(),
        source_path: source_file.display().to_string(),
        declared_in: declared_in.to_string(),
        mtime: metadata.mtime,
        sha256: metadata.sha256,
        is_recent: metadata.is_recent,
        is_baseline_new: false,
        risk_flags,
        confidence,
    });
}

#[allow(clippy::too_many_arguments)]
fn push_tomcat_file_component(
    resolved: &ResolvedRun,
    inventory: &mut RuntimeInventory,
    component_type: &str,
    name: impl Into<String>,
    class_name: impl Into<String>,
    url_pattern: impl Into<String>,
    source_file: &Path,
    source_path: &Path,
    declared_in: impl Into<String>,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let name = name.into();
    let class_name = class_name.into();
    let url_pattern = url_pattern.into();
    let declared_in = declared_in.into();
    let metadata = inventory.cached_artifact_metadata(resolved, source_file);
    let mut flags = extra_flags.to_vec();
    if metadata.is_recent {
        flags.push("recent_change");
    }
    if suspicious_component_name(&name) {
        flags.push("suspicious_name");
    }
    if suspicious_component_name(&class_name) {
        flags.push("suspicious_class");
    }
    let risk_flags = join_flags(flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        "tomcat",
        component_type,
        &name,
        &class_name,
        &source_path.display().to_string(),
        &metadata.sha256,
    ]);
    inventory.tomcat_components.push(TomcatComponentRow {
        component_id,
        runtime_type: "tomcat".to_string(),
        component_type: component_type.to_string(),
        name,
        class_name,
        url_pattern,
        source_file: source_file.display().to_string(),
        source_path: source_path.display().to_string(),
        declared_in,
        mtime: metadata.mtime,
        sha256: metadata.sha256,
        is_recent: metadata.is_recent,
        is_baseline_new: false,
        risk_flags,
        confidence,
    });
}

fn class_name_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .replace('$', ".")
}
