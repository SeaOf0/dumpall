use std::fs;
use std::path::Path;

use crate::config::ResolvedRun;
use crate::model::CollectionError;

use super::{
    artifact_metadata, component_id, confidence_for_flags, display_path, extension,
    is_broad_mapping, join_flags, push_warning, record_seen_file, suspicious_component_name,
    tag_blocks, tag_starts, xml_attr, AspNetHandlerRow, IisModuleRow, RuntimeInventory,
};

pub const COLLECTOR_SCOPE: &str = "aspnet_handlers";

#[derive(Debug, Clone)]
pub(crate) struct SiteContext {
    pub site_name: String,
    pub app_pool: String,
    pub physical_path: String,
}

pub(crate) fn collect_site_web_config(
    resolved: &ResolvedRun,
    site: &SiteContext,
    web_config: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let content = match fs::read_to_string(web_config) {
        Ok(content) => content,
        Err(error) => {
            push_warning(
                inventory,
                errors,
                "aspnet",
                web_config,
                "read_file",
                "ASP.NET web.config could not be read",
                Some(error.to_string()),
            );
            return Ok(());
        }
    };

    parse_web_config(resolved, site, web_config, &content, inventory);
    collect_bin_dlls(
        resolved,
        site,
        web_config.parent().unwrap_or(web_config),
        inventory,
    );
    Ok(())
}

pub(crate) fn parse_web_config(
    resolved: &ResolvedRun,
    site: &SiteContext,
    source_config: &Path,
    xml: &str,
    inventory: &mut RuntimeInventory,
) {
    for modules_block in tag_blocks(xml, "modules") {
        for tag in tag_starts(modules_block, "add") {
            let name = xml_attr(tag, "name").unwrap_or_default();
            let path = first_attr(tag, &["image", "type", "preCondition"]);
            let precondition = xml_attr(tag, "preCondition").unwrap_or_default();
            push_iis_module_row(
                resolved,
                inventory,
                site,
                "site_module",
                &name,
                &path,
                &precondition,
                source_config,
                &["site_module", "web_config_change"],
            );
        }
    }

    for handlers_block in tag_blocks(xml, "handlers") {
        for tag in tag_starts(handlers_block, "add") {
            push_handler_from_tag(
                resolved,
                inventory,
                site,
                source_config,
                tag,
                &["site_handler", "web_config_change"],
            );
        }
    }
}

pub(crate) fn push_handler_from_tag(
    resolved: &ResolvedRun,
    inventory: &mut RuntimeInventory,
    site: &SiteContext,
    source_config: &Path,
    tag: &str,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let name = xml_attr(tag, "name").unwrap_or_else(|| "handler".to_string());
    let route_path = xml_attr(tag, "path").unwrap_or_default();
    let verb = xml_attr(tag, "verb").unwrap_or_default();
    let resource_type = xml_attr(tag, "resourceType").unwrap_or_default();
    let handler_target = first_attr(tag, &["scriptProcessor", "type", "modules"]);
    let metadata = artifact_metadata(resolved, source_config, resolved.safety.max_file_size_mb);
    let mut flags = extra_flags.to_vec();
    if is_broad_mapping(&route_path) || is_broad_mapping(&verb) {
        flags.push("broad_mapping");
    }
    if suspicious_component_name(&name)
        || suspicious_component_name(&route_path)
        || suspicious_component_name(&handler_target)
    {
        flags.push("suspicious_name");
    }
    if !handler_target.is_empty() {
        flags.push("handler_script_processor");
    }
    if path_looks_native(&handler_target) {
        flags.push("native_image_path");
        flags.push("unknown_signature");
    }
    if metadata.is_recent {
        flags.push("recent_change");
    }
    let risk_flags = join_flags(flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        "aspnet",
        "handler",
        &site.site_name,
        &site.app_pool,
        &name,
        &route_path,
        &verb,
        &handler_target,
        &metadata.sha256,
    ]);
    inventory.aspnet_handlers.push(AspNetHandlerRow {
        component_id,
        site_name: site.site_name.clone(),
        app_pool: site.app_pool.clone(),
        component_type: "handler".to_string(),
        name,
        path: route_path,
        verb,
        resource_type,
        source_config: source_config.display().to_string(),
        mtime: metadata.mtime,
        sha256: metadata.sha256,
        risk_flags,
        confidence,
    });
}

pub(crate) fn collect_bin_dlls(
    resolved: &ResolvedRun,
    site: &SiteContext,
    site_root: &Path,
    inventory: &mut RuntimeInventory,
) {
    let bin = site_root.join("bin");
    if !bin.is_dir() {
        return;
    }
    for file in super::walk_files(&bin, 2) {
        if extension(&file) != "dll" {
            continue;
        }
        push_iis_module_row(
            resolved,
            inventory,
            site,
            "bin_dll",
            file.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("site.dll"),
            &display_path(&file),
            "",
            &file,
            &["bin_dll", "unknown_signature"],
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_iis_module_row(
    resolved: &ResolvedRun,
    inventory: &mut RuntimeInventory,
    site: &SiteContext,
    component_type: &str,
    name: &str,
    path: &str,
    precondition: &str,
    source_config: &Path,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let metadata_path = metadata_path(path, source_config);
    let metadata = artifact_metadata(resolved, metadata_path, resolved.safety.max_file_size_mb);
    let mut flags = extra_flags.to_vec();
    if metadata.is_recent {
        flags.push("recent_change");
    }
    if suspicious_component_name(name) || suspicious_component_name(path) {
        flags.push("suspicious_name");
    }
    if path_looks_native(path) {
        flags.push("native_image_path");
        flags.push("unknown_signature");
    }
    let signature_status = if path_looks_native(path) {
        "unknown"
    } else {
        "not_checked"
    };
    let risk_flags = join_flags(flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        "iis",
        component_type,
        &site.site_name,
        &site.app_pool,
        name,
        path,
        precondition,
        &metadata.sha256,
    ]);
    inventory.iis_modules.push(IisModuleRow {
        component_id,
        site_name: site.site_name.clone(),
        app_pool: site.app_pool.clone(),
        component_type: component_type.to_string(),
        name: name.to_string(),
        path: path.to_string(),
        precondition: precondition.to_string(),
        source_config: source_config.display().to_string(),
        mtime: metadata.mtime,
        sha256: metadata.sha256,
        signature_status: signature_status.to_string(),
        is_recent: metadata.is_recent,
        is_baseline_new: false,
        risk_flags,
        confidence,
    });
}

fn first_attr(tag: &str, names: &[&str]) -> String {
    names
        .iter()
        .filter_map(|name| xml_attr(tag, name))
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

fn metadata_path<'a>(path: &'a str, fallback: &'a Path) -> &'a Path {
    let candidate = Path::new(path);
    if candidate.is_file() {
        candidate
    } else {
        fallback
    }
}

fn path_looks_native(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.contains(".dll ")
        || lower.contains(".exe ")
}
