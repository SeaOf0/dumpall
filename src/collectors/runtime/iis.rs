use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::ResolvedRun;
use crate::model::CollectionError;

use super::{push_warning, tag_blocks, tag_starts, xml_attr, RuntimeInventory};

pub const COLLECTOR_SCOPE: &str = "iis_modules";

pub(crate) fn collect_iis_config(
    resolved: &ResolvedRun,
    iis_config: &Path,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let config_path = resolve_config_path(iis_config);
    if !config_path.exists() {
        push_warning(
            inventory,
            errors,
            "iis",
            iis_config,
            "discover",
            "IIS applicationHost.config path does not exist",
            Some(
                "Provide a readable --iis-config path or an offline copy of applicationHost.config."
                    .to_string(),
            ),
        );
        return Ok(());
    }
    if !config_path.is_file() {
        push_warning(
            inventory,
            errors,
            "iis",
            &config_path,
            "discover",
            "IIS config path is not a file",
            Some(
                "IIS collection expects applicationHost.config or a directory containing it."
                    .to_string(),
            ),
        );
        return Ok(());
    }

    let content = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            push_warning(
                inventory,
                errors,
                "iis",
                &config_path,
                "read_file",
                "IIS applicationHost.config could not be read",
                Some(error.to_string()),
            );
            return Ok(());
        }
    };

    parse_application_host_config(resolved, &config_path, &content, inventory, errors)?;
    Ok(())
}

fn resolve_config_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        for relative in [
            "applicationHost.config",
            "config/applicationHost.config",
            "inetsrv/config/applicationHost.config",
        ] {
            let candidate = input.join(relative);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    input.to_path_buf()
}

fn parse_application_host_config(
    resolved: &ResolvedRun,
    config_path: &Path,
    xml: &str,
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
) -> crate::error::Result<()> {
    let app_pools = parse_app_pools(xml);
    let sites = parse_sites(xml, &app_pools);
    let global_site = super::aspnet::SiteContext {
        site_name: "global".to_string(),
        app_pool: String::new(),
        physical_path: String::new(),
    };

    collect_global_modules(resolved, config_path, xml, &global_site, inventory);
    collect_global_handlers(resolved, config_path, xml, &global_site, inventory);
    collect_fastcgi(resolved, config_path, xml, &global_site, inventory);

    for site in &sites {
        if is_privileged_app_pool(&site.app_pool, &app_pools) {
            push_app_pool_identity_row(resolved, config_path, site, inventory, &app_pools);
        }
        // physicalPath 常见为 %SystemDrive%\inetpub\wwwroot 等变量形式：
        // 先展开变量（在线命中真实值；离线缺失登记错误并保持跳过），
        // 再判目录存在，变量不再导致整站 web.config/bin 证据静默丢失。
        let expanded_root = expand_iis_path_variables(&site.physical_path, errors)
            .as_deref()
            .and_then(physical_site_root);
        if let Some(site_root) = expanded_root {
            let web_config = site_root.join("web.config");
            if web_config.is_file() {
                super::aspnet::collect_site_web_config(
                    resolved,
                    site,
                    &web_config,
                    inventory,
                    errors,
                )?;
            } else {
                super::aspnet::collect_bin_dlls(resolved, site, &site_root, inventory);
            }
        }
    }
    Ok(())
}

fn collect_global_modules(
    resolved: &ResolvedRun,
    config_path: &Path,
    xml: &str,
    site: &super::aspnet::SiteContext,
    inventory: &mut RuntimeInventory,
) {
    for block in tag_blocks(xml, "globalModules") {
        for tag in tag_starts(block, "add") {
            let name = xml_attr(tag, "name").unwrap_or_else(|| "global_module".to_string());
            let image = xml_attr(tag, "image").unwrap_or_default();
            let precondition = xml_attr(tag, "preCondition").unwrap_or_default();
            super::aspnet::push_iis_module_row(
                resolved,
                inventory,
                site,
                "global_module",
                &name,
                &image,
                &precondition,
                config_path,
                &["global_module"],
            );
        }
    }

    for block in tag_blocks(xml, "modules") {
        for tag in tag_starts(block, "add") {
            let name = xml_attr(tag, "name").unwrap_or_else(|| "module".to_string());
            let path = xml_attr(tag, "type")
                .or_else(|| xml_attr(tag, "image"))
                .unwrap_or_default();
            let precondition = xml_attr(tag, "preCondition").unwrap_or_default();
            super::aspnet::push_iis_module_row(
                resolved,
                inventory,
                site,
                "module",
                &name,
                &path,
                &precondition,
                config_path,
                &["global_module"],
            );
        }
    }
}

fn collect_global_handlers(
    resolved: &ResolvedRun,
    config_path: &Path,
    xml: &str,
    site: &super::aspnet::SiteContext,
    inventory: &mut RuntimeInventory,
) {
    for block in tag_blocks(xml, "handlers") {
        for tag in tag_starts(block, "add") {
            super::aspnet::push_handler_from_tag(
                resolved,
                inventory,
                site,
                config_path,
                tag,
                &["global_handler"],
            );
        }
    }
}

fn collect_fastcgi(
    resolved: &ResolvedRun,
    config_path: &Path,
    xml: &str,
    site: &super::aspnet::SiteContext,
    inventory: &mut RuntimeInventory,
) {
    for block in tag_blocks(xml, "fastCgi") {
        for tag in tag_starts(block, "application") {
            let full_path = xml_attr(tag, "fullPath").unwrap_or_default();
            let arguments = xml_attr(tag, "arguments").unwrap_or_default();
            let name = if arguments.is_empty() {
                full_path.clone()
            } else {
                format!("{full_path} {arguments}")
            };
            super::aspnet::push_iis_module_row(
                resolved,
                inventory,
                site,
                "fastcgi",
                &name,
                &full_path,
                "",
                config_path,
                &["fastcgi", "native_image_path"],
            );
        }
    }
}

fn push_app_pool_identity_row(
    resolved: &ResolvedRun,
    config_path: &Path,
    site: &super::aspnet::SiteContext,
    inventory: &mut RuntimeInventory,
    app_pools: &BTreeMap<String, AppPool>,
) {
    let pool = app_pools.get(&site.app_pool);
    let identity = pool
        .map(|pool| pool.identity_label())
        .unwrap_or_else(|| site.app_pool.clone());
    super::aspnet::push_iis_module_row(
        resolved,
        inventory,
        site,
        "app_pool_identity",
        &site.app_pool,
        &identity,
        "",
        config_path,
        &["privileged_app_pool_identity"],
    );
}

fn parse_sites(
    xml: &str,
    app_pools: &BTreeMap<String, AppPool>,
) -> Vec<super::aspnet::SiteContext> {
    let mut sites = Vec::new();
    for site_block in tag_blocks(xml, "site") {
        let site_start = tag_starts(site_block, "site")
            .into_iter()
            .next()
            .unwrap_or("");
        let site_name = xml_attr(site_start, "name").unwrap_or_else(|| "site".to_string());
        for app_start in tag_starts(site_block, "application") {
            let app_pool = xml_attr(app_start, "applicationPool")
                .or_else(|| xml_attr(app_start, "appPool"))
                .unwrap_or_else(|| default_app_pool(app_pools));
            let physical_path = tag_starts(site_block, "virtualDirectory")
                .into_iter()
                .filter(|tag| {
                    xml_attr(tag, "path")
                        .map(|path| path == "/")
                        .unwrap_or(true)
                })
                .find_map(|tag| xml_attr(tag, "physicalPath"))
                .unwrap_or_default();
            sites.push(super::aspnet::SiteContext {
                site_name: site_name.clone(),
                app_pool,
                physical_path,
            });
        }
    }
    sites
}

#[derive(Debug, Clone, Default)]
struct AppPool {
    identity_type: String,
    user_name: String,
}

impl AppPool {
    fn identity_label(&self) -> String {
        if self.user_name.is_empty() {
            self.identity_type.clone()
        } else {
            format!("{}:{}", self.identity_type, self.user_name)
        }
    }
}

fn parse_app_pools(xml: &str) -> BTreeMap<String, AppPool> {
    let mut app_pools = BTreeMap::new();
    for block in tag_blocks(xml, "applicationPools") {
        for tag in tag_starts(block, "add") {
            let name = xml_attr(tag, "name").unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let mut pool = AppPool {
                identity_type: xml_attr(tag, "identityType").unwrap_or_default(),
                user_name: xml_attr(tag, "userName").unwrap_or_default(),
            };
            if let Some(process_model) = process_model_for_pool(block, &name) {
                if pool.identity_type.is_empty() {
                    pool.identity_type =
                        xml_attr(process_model, "identityType").unwrap_or_default();
                }
                if pool.user_name.is_empty() {
                    pool.user_name = xml_attr(process_model, "userName").unwrap_or_default();
                }
            }
            app_pools.insert(name, pool);
        }
    }
    app_pools
}

fn process_model_for_pool<'a>(
    application_pools_block: &'a str,
    pool_name: &str,
) -> Option<&'a str> {
    tag_blocks(application_pools_block, "add")
        .into_iter()
        .find(|block| {
            tag_starts(block, "add")
                .into_iter()
                .next()
                .and_then(|tag| xml_attr(tag, "name"))
                .map(|name| name == pool_name)
                .unwrap_or(false)
        })
        .and_then(|block| tag_starts(block, "processModel").into_iter().next())
}

fn default_app_pool(app_pools: &BTreeMap<String, AppPool>) -> String {
    if app_pools.contains_key("DefaultAppPool") {
        "DefaultAppPool".to_string()
    } else {
        app_pools
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }
}

fn is_privileged_app_pool(app_pool: &str, app_pools: &BTreeMap<String, AppPool>) -> bool {
    let Some(pool) = app_pools.get(app_pool) else {
        return false;
    };
    let identity = pool.identity_label().to_ascii_lowercase();
    identity.contains("localsystem")
        || identity.contains("administrator")
        || identity.contains("domain admins")
        || identity.contains("system:")
}

/// 站点物理根目录：展开 `%SystemDrive%` 等 IIS 配置常见环境变量后再判定。
/// 被检机即分析目标机（在线 triage/collect）时 `env::var` 命中真实值；
/// 离线分析机上变量缺失则保留跳过语义并登记说明，不猜路径。
fn physical_site_root(value: &str) -> Option<PathBuf> {
    if value.trim().is_empty() || value.contains('%') {
        return None;
    }
    let path = PathBuf::from(value);
    path.is_dir().then_some(path)
}

/// 展开 IIS applicationHost.config 中 `%Variable%` 形式的路径变量。
/// 返回 None 表示存在无法展开的变量（保持跳过语义）。
fn expand_iis_path_variables(
    value: &str,
    errors: &mut Vec<CollectionError>,
) -> Option<String> {
    let mut unresolved: Option<String> = None;
    let expanded = replace_percent_variables(value, |name| {
        // 变量名大小写不敏感（%SystemDrive% 与 %systemdrive% 等价）。
        if let Ok(found) = std::env::var(name) {
            return Some(found);
        }
        let upper = name.to_ascii_uppercase();
        std::env::var(&upper).ok().or_else(|| {
            unresolved.get_or_insert_with(|| upper.clone());
            None
        })
    });
    if let Some(missing) = unresolved {
        errors.push(crate::collectors::collection_error(
            "iis",
            value.to_string(),
            "discover",
            "site physicalPath references an environment variable that is not defined on this machine; the site root was skipped",
            Some(format!(
                "unresolved variable: %{missing}%; offline analysis hosts should rerun on the target machine or expand the variable manually"
            )),
        ));
        return None;
    }
    Some(expanded)
}

/// 逐段替换 `%Var%`（支持同一字符串中的多个变量；未成对的 % 原样保留）。
fn replace_percent_variables<F>(value: &str, mut resolver: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        match after_start.find('%') {
            Some(end) => {
                let name = &after_start[..end];
                if name.is_empty() {
                    output.push('%');
                } else {
                    let replacement = resolver(name).unwrap_or_else(|| format!("%{name}%"));
                    output.push_str(&replacement);
                }
                rest = &after_start[end + 1..];
            }
            None => {
                output.push('%');
                output.push_str(after_start);
                return output;
            }
        }
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_known_variables_case_insensitively() {
        let expanded = replace_percent_variables(
            "%SystemDrive%\\inetpub\\wwwroot",
            |name| {
                if name.eq_ignore_ascii_case("SystemDrive") {
                    Some("C:".to_string())
                } else {
                    None
                }
            },
        );
        assert_eq!(expanded, "C:\\inetpub\\wwwroot");
    }

    #[test]
    fn keeps_unknown_variable_placeholder() {
        let expanded =
            replace_percent_variables("%MissingVar%\\site", |name| {
                if name == "MissingVar" {
                    None
                } else {
                    Some(String::new())
                }
            });
        assert_eq!(expanded, "%MissingVar%\\site");
    }

    #[test]
    fn expands_multiple_variables_in_one_path() {
        let expanded = replace_percent_variables("%A%-%B%", |name| match name {
            "A" => Some("1".to_string()),
            "B" => Some("2".to_string()),
            _ => None,
        });
        assert_eq!(expanded, "1-2");
    }

    #[test]
    fn unpaired_percent_stays_literal() {
        assert_eq!(replace_percent_variables("50% off", |_| None), "50% off");
        assert_eq!(replace_percent_variables("a%%b", |_| None), "a%b");
    }

    #[test]
    fn empty_physical_path_or_missing_dir_yields_none() {
        assert!(physical_site_root("").is_none());
        assert!(physical_site_root("%SystemDrive%\\nonexistent-path").is_none());
    }
}
