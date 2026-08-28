use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::collector_trait::{
    path_strings, runtime_input_paths, CollectOutput, CollectPlan, Collector, Discovery,
    ResourceBudget,
};
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

pub mod aspnet;
pub mod iis;
pub mod java;
pub mod spring;
pub mod tomcat;

const MAX_RUNTIME_FILES_PER_RUN: usize = 50_000;

pub struct RuntimeCollector;

impl Collector for RuntimeCollector {
    fn name(&self) -> &'static str {
        "runtime"
    }

    fn discover(&self, ctx: &ResolvedRun) -> Result<Vec<Discovery>> {
        let discoveries = runtime_input_paths(ctx)
            .into_iter()
            .map(|path| Discovery {
                collector: self.name().to_string(),
                kind: "runtime_input".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "v1.2 runtime path argument".to_string(),
            })
            .collect();
        Ok(discoveries)
    }

    fn plan(&self, ctx: &ResolvedRun, discoveries: &[Discovery]) -> Result<CollectPlan> {
        let mut inputs = discoveries
            .iter()
            .filter_map(|discovery| discovery.path.clone())
            .collect::<Vec<_>>();
        if inputs.is_empty() && ctx.runtime_scan_enabled() {
            inputs.push("auto-discovery from process/config paths".to_string());
        }

        Ok(CollectPlan {
            collector: self.name().to_string(),
            enabled: ctx.runtime_scan_enabled(),
            readonly: true,
            dry_run_supported: true,
            active_check_allowed: ctx.runtime_active_check,
            summary: if ctx.runtime_scan_enabled() {
                "Plan Java/Tomcat/Spring/IIS/ASP.NET component inventory without JVM attach or memory dump by default.".to_string()
            } else {
                "Runtime component collector disabled for this profile.".to_string()
            },
            inputs,
            outputs: vec![
                "runtime/java_components.csv".to_string(),
                "runtime/tomcat_components.csv".to_string(),
                "runtime/spring_mappings.csv".to_string(),
                "runtime/iis_modules.csv".to_string(),
                "runtime/aspnet_handlers.csv".to_string(),
                "runtime/runtime_warnings.csv".to_string(),
                "runtime/component_diff.csv".to_string(),
            ],
            budget: ResourceBudget {
                max_files: None,
                max_records: None,
                max_file_size_mb: Some(ctx.safety.max_file_size_mb),
                active_check_allowed: ctx.runtime_active_check,
            },
        })
    }

    fn collect(&self, _ctx: &ResolvedRun, plan: &CollectPlan) -> Result<CollectOutput> {
        Ok(CollectOutput {
            collector: self.name().to_string(),
            files_scanned: 0,
            records_emitted: 0,
            notes: vec![format!(
                "{} inventory is implemented by the v1.2 runtime pipeline when the collector is executed through the main run flow.",
                plan.collector
            )],
            errors: Vec::new(),
        })
    }
}

#[derive(Debug, Default)]
pub struct RuntimeCollectionReport {
    pub files_scanned: u64,
    pub records_emitted: u64,
    pub errors: Vec<CollectionError>,
    pub notes: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeInventory {
    pub java_components: Vec<JavaComponentRow>,
    pub tomcat_components: Vec<TomcatComponentRow>,
    pub spring_mappings: Vec<SpringMappingRow>,
    pub iis_modules: Vec<IisModuleRow>,
    pub aspnet_handlers: Vec<AspNetHandlerRow>,
    pub warnings: Vec<RuntimeWarningRow>,
    pub diffs: Vec<ComponentDiffRow>,
    files_seen: usize,
    /// 按路径 memoize 的工件元数据（mtime/sha256/is_recent）：
    /// 同一 web.xml 会被 filter/servlet/mapping 等多个组件行引用，
    /// 缓存避免每个组件重复读盘+哈希同一文件。
    metadata_cache: HashMap<PathBuf, ArtifactMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct JavaComponentRow {
    pub component_id: String,
    pub runtime_type: String,
    pub component_type: String,
    pub name: String,
    pub class_name: String,
    pub source_file: String,
    pub source_path: String,
    pub declared_in: String,
    pub mtime: String,
    pub sha256: String,
    pub is_recent: bool,
    pub is_baseline_new: bool,
    pub risk_flags: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TomcatComponentRow {
    pub component_id: String,
    pub runtime_type: String,
    pub component_type: String,
    pub name: String,
    pub class_name: String,
    pub url_pattern: String,
    pub source_file: String,
    pub source_path: String,
    pub declared_in: String,
    pub mtime: String,
    pub sha256: String,
    pub is_recent: bool,
    pub is_baseline_new: bool,
    pub risk_flags: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SpringMappingRow {
    pub component_id: String,
    pub component_type: String,
    pub route: String,
    pub http_method: String,
    pub class_name: String,
    pub jar_path: String,
    pub source: String,
    pub is_from_actuator: bool,
    pub is_from_log: bool,
    pub is_from_static_archive: bool,
    pub mtime: String,
    pub sha256: String,
    pub risk_flags: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IisModuleRow {
    pub component_id: String,
    pub site_name: String,
    pub app_pool: String,
    pub component_type: String,
    pub name: String,
    pub path: String,
    pub precondition: String,
    pub source_config: String,
    pub mtime: String,
    pub sha256: String,
    pub signature_status: String,
    pub is_recent: bool,
    pub is_baseline_new: bool,
    pub risk_flags: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AspNetHandlerRow {
    pub component_id: String,
    pub site_name: String,
    pub app_pool: String,
    pub component_type: String,
    pub name: String,
    pub path: String,
    pub verb: String,
    pub resource_type: String,
    pub source_config: String,
    pub mtime: String,
    pub sha256: String,
    pub risk_flags: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimeWarningRow {
    pub timestamp: String,
    pub target: String,
    pub path: String,
    pub message: String,
    pub evidence_gap: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ComponentDiffRow {
    pub component_id: String,
    pub component_type: String,
    pub name: String,
    pub path: String,
    pub change_type: String,
    pub baseline_path: String,
    pub current_hash: String,
    pub baseline_hash: String,
    pub risk_flags: String,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ArtifactMetadata {
    pub mtime: String,
    pub sha256: String,
    pub is_recent: bool,
}

#[derive(Debug, Default)]
struct BaselineIndex {
    path: Option<String>,
    hashes: HashSet<String>,
    keys: HashSet<String>,
}

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<RuntimeCollectionReport> {
    logger.log("collector: runtime Java/Tomcat/Spring/IIS/ASP.NET static inventory")?;
    let baseline = BaselineIndex::load(resolved.component_baseline.as_deref())?;
    let mut inventory = RuntimeInventory::default();
    let mut errors = Vec::new();

    if let Some(java_home) = &resolved.java_home {
        java::collect_java_home(resolved, java_home, &mut inventory, &mut errors)?;
    }
    for tomcat_base in &resolved.tomcat_base {
        tomcat::collect_tomcat_base(resolved, tomcat_base, &mut inventory, &mut errors)?;
    }
    for spring_path in &resolved.spring_app_path {
        spring::collect_spring_app_path(resolved, spring_path, &mut inventory, &mut errors)?;
    }
    if !resolved.app_log_paths.is_empty() {
        spring::collect_spring_log_mappings(resolved, &mut inventory, &mut errors)?;
    }
    if let Some(iis_config) = &resolved.iis_config {
        iis::collect_iis_config(resolved, iis_config, &mut inventory, &mut errors)?;
    }

    apply_baseline(&baseline, &mut inventory);
    write_inventory(layout, &inventory)?;

    let records_emitted = inventory.java_components.len()
        + inventory.tomcat_components.len()
        + inventory.spring_mappings.len()
        + inventory.iis_modules.len()
        + inventory.aspnet_handlers.len();
    Ok(RuntimeCollectionReport {
        files_scanned: inventory.files_seen as u64,
        records_emitted: records_emitted as u64,
        errors,
        notes: vec![format!(
            "runtime inventory completed: {} Java artifact row(s), {} Tomcat component row(s), {} Spring mapping row(s), {} IIS module row(s), {} ASP.NET handler row(s), {} warning(s).",
            inventory.java_components.len(),
            inventory.tomcat_components.len(),
            inventory.spring_mappings.len(),
            inventory.iis_modules.len(),
            inventory.aspnet_handlers.len(),
            inventory.warnings.len()
        )],
    })
}

pub fn manual_inputs(ctx: &ResolvedRun) -> Vec<String> {
    path_strings(&runtime_input_paths(ctx))
}

pub(crate) fn push_warning(
    inventory: &mut RuntimeInventory,
    errors: &mut Vec<CollectionError>,
    target: &str,
    path: &Path,
    operation: &str,
    message: &str,
    detail: impl Into<Option<String>>,
) {
    let detail = detail.into();
    inventory.warnings.push(RuntimeWarningRow {
        timestamp: crate::time_utils::now_iso(),
        target: target.to_string(),
        path: path.display().to_string(),
        message: message.to_string(),
        evidence_gap: true,
        detail: detail.clone().unwrap_or_default(),
    });
    errors.push(crate::collectors::collection_error(
        "runtime",
        path.display().to_string(),
        operation,
        message,
        detail,
    ));
}

pub(crate) fn record_seen_file(inventory: &mut RuntimeInventory) -> bool {
    if inventory.files_seen >= MAX_RUNTIME_FILES_PER_RUN {
        return false;
    }
    inventory.files_seen += 1;
    true
}

pub(crate) fn artifact_metadata(
    resolved: &ResolvedRun,
    path: &Path,
    max_file_size_mb: u64,
) -> ArtifactMetadata {
    let metadata = path.metadata().ok();
    let modified = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok());
    let mtime = file_modified_iso(modified);
    let size_bytes = metadata
        .as_ref()
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let max_bytes = max_file_size_mb.saturating_mul(1024 * 1024);
    let sha256 = if size_bytes > 0 && size_bytes <= max_bytes {
        sha256_file(path).unwrap_or_default()
    } else {
        String::new()
    };

    ArtifactMetadata {
        mtime,
        sha256,
        is_recent: is_recent(modified, resolved),
    }
}

impl RuntimeInventory {
    /// 按路径 memoize 的 artifact_metadata：同一文件（典型为 web.xml）被
    /// 多个组件行引用时只读盘+哈希一次。工具只读、运行期内视为内容不变。
    pub(crate) fn cached_artifact_metadata(
        &mut self,
        resolved: &ResolvedRun,
        path: &Path,
    ) -> ArtifactMetadata {
        if let Some(hit) = self.metadata_cache.get(path) {
            return hit.clone();
        }
        let metadata = artifact_metadata(resolved, path, resolved.safety.max_file_size_mb);
        self.metadata_cache.insert(path.to_path_buf(), metadata.clone());
        metadata
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_java_artifact(
    inventory: &mut RuntimeInventory,
    resolved: &ResolvedRun,
    runtime_type: &str,
    component_type: &str,
    name: impl Into<String>,
    class_name: impl Into<String>,
    source_file: &Path,
    source_path: impl Into<String>,
    declared_in: impl Into<String>,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let name = name.into();
    let class_name = class_name.into();
    let source_path = source_path.into();
    let declared_in = declared_in.into();
    let metadata = artifact_metadata(resolved, source_file, resolved.safety.max_file_size_mb);
    let risk_flags = risk_flags_for_artifact(&name, &class_name, &metadata, extra_flags);
    let confidence = confidence_for_flags(&risk_flags);
    let component_id = component_id(&[
        runtime_type,
        component_type,
        &name,
        &class_name,
        &source_path,
        &metadata.sha256,
    ]);
    inventory.java_components.push(JavaComponentRow {
        component_id,
        runtime_type: runtime_type.to_string(),
        component_type: component_type.to_string(),
        name,
        class_name,
        source_file: source_file.display().to_string(),
        source_path,
        declared_in,
        mtime: metadata.mtime,
        sha256: metadata.sha256,
        is_recent: metadata.is_recent,
        is_baseline_new: false,
        risk_flags,
        confidence,
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn push_java_virtual_artifact(
    inventory: &mut RuntimeInventory,
    runtime_type: &str,
    component_type: &str,
    name: impl Into<String>,
    class_name: impl Into<String>,
    source_file: impl Into<String>,
    source_path: impl Into<String>,
    declared_in: impl Into<String>,
    mtime: impl Into<String>,
    sha256: impl Into<String>,
    is_recent: bool,
    extra_flags: &[&str],
) {
    if !record_seen_file(inventory) {
        return;
    }
    let name = name.into();
    let class_name = class_name.into();
    let source_file = source_file.into();
    let source_path = source_path.into();
    let declared_in = declared_in.into();
    let mtime = mtime.into();
    let sha256 = sha256.into();
    let mut flags = extra_flags.to_vec();
    if is_recent {
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
        runtime_type,
        component_type,
        &name,
        &class_name,
        &source_path,
        &sha256,
    ]);
    inventory.java_components.push(JavaComponentRow {
        component_id,
        runtime_type: runtime_type.to_string(),
        component_type: component_type.to_string(),
        name,
        class_name,
        source_file,
        source_path,
        declared_in,
        mtime,
        sha256,
        is_recent,
        is_baseline_new: false,
        risk_flags,
        confidence,
    });
}

pub(crate) fn component_id(parts: &[&str]) -> String {
    let joined = parts.join("|");
    let digest = Sha256::digest(joined.as_bytes());
    let mut suffix = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    format!("RT-{suffix}")
}

/// 文件 SHA-256：8KB 分块流式计算，避免把大 jar/war/dll 整读进内存。
pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    Ok(output)
}

pub(crate) fn file_modified_iso(modified: Option<SystemTime>) -> String {
    modified
        .map(system_time_to_iso)
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn walk_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk_files_inner(root, 0, max_depth, &mut files);
    files
}

pub(crate) fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub(crate) fn text_between_tags(block: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"(?is)<{tag}(?:[\s/][^>]*)?>(.*?)</{tag}>");
    let regex = regex::Regex::new(&pattern).ok()?;
    regex
        .captures(block)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml_text(value.as_str()))
        .filter(|value| !value.trim().is_empty())
}

/// 精确标签起始匹配：标签名后必须紧跟空白/`/`/`>`，否则 `<filter\b`
/// 这类 `\b` 写法会把 `<filter-mapping>`、`<servlet-mapping>` 的开标签
/// 当成 `<filter>`/`<servlet>` 块的起始（regex crate 无 lookahead，
/// 用"标签名后首个字符属于 [\s/>]"的字符类等价实现两步判定）。
pub(crate) fn tag_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let Ok(regex) = regex::Regex::new(&format!(
        r"(?is)<{tag}(?:[\s/][^>]*)?>.*?</{tag}>"
    )) else {
        return Vec::new();
    };
    regex.find_iter(xml).map(|item| item.as_str()).collect()
}

pub(crate) fn tag_starts<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let Ok(regex) = regex::Regex::new(&format!(r"(?is)<{tag}(?:[\s/][^>]*)?>")) else {
        return Vec::new();
    };
    regex.find_iter(xml).map(|item| item.as_str()).collect()
}

pub(crate) fn xml_attr(tag_start: &str, attr: &str) -> Option<String> {
    let Ok(regex) = regex::Regex::new(&format!(r#"(?i)\b{attr}\s*=\s*["']([^"']+)["']"#)) else {
        return None;
    };
    regex
        .captures(tag_start)
        .and_then(|captures| captures.get(1))
        .map(|value| decode_xml_text(value.as_str()))
}

pub(crate) fn suspicious_component_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "memshell",
        "memoryshell",
        "webshell",
        "cmd",
        "shell",
        "exec",
        "payload",
        "inject",
        "agent",
        "loader",
        "godzilla",
        "behinder",
        "rebeyond",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn is_broad_mapping(value: &str) -> bool {
    let value = value.trim();
    matches!(value, "/" | "/*" | "*" | "/**")
}

pub(crate) fn confidence_for_flags(flags: &str) -> String {
    if flags.contains("broad_mapping")
        || flags.contains("management_endpoint_exposure")
        || flags.contains("suspicious_name")
        || flags.contains("suspicious_class")
        || flags.contains("handler_script_processor")
        || flags.contains("privileged_app_pool_identity")
        || flags.contains("baseline_new")
    {
        "high".to_string()
    } else if flags.contains("recent_change")
        || flags.contains("webapps_artifact")
        || flags.contains("work_temp_artifact")
        || flags.contains("static_archive_component")
        || flags.contains("native_image_path")
        || flags.contains("unknown_signature")
        || flags.contains("web_config_change")
    {
        "medium".to_string()
    } else {
        "low".to_string()
    }
}

pub(crate) fn join_flags(mut flags: Vec<&str>) -> String {
    flags.sort_unstable();
    flags.dedup();
    flags.join(";")
}

pub(crate) fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn write_inventory(layout: &OutputLayout, inventory: &RuntimeInventory) -> Result<()> {
    if inventory.java_components.is_empty() {
        writers::write_text(
            &layout.java_components,
            "component_id,runtime_type,component_type,name,class_name,source_file,source_path,declared_in,mtime,sha256,is_recent,is_baseline_new,risk_flags,confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.java_components, &inventory.java_components)?;
    }

    if inventory.tomcat_components.is_empty() {
        writers::write_text(
            &layout.tomcat_components,
            "component_id,runtime_type,component_type,name,class_name,url_pattern,source_file,source_path,declared_in,mtime,sha256,is_recent,is_baseline_new,risk_flags,confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.tomcat_components, &inventory.tomcat_components)?;
    }

    if inventory.spring_mappings.is_empty() {
        writers::write_text(
            &layout.spring_mappings,
            "component_id,component_type,route,http_method,class_name,jar_path,source,is_from_actuator,is_from_log,is_from_static_archive,mtime,sha256,risk_flags,confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.spring_mappings, &inventory.spring_mappings)?;
    }

    if inventory.iis_modules.is_empty() {
        writers::write_text(
            &layout.iis_modules,
            "component_id,site_name,app_pool,component_type,name,path,precondition,source_config,mtime,sha256,signature_status,is_recent,is_baseline_new,risk_flags,confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.iis_modules, &inventory.iis_modules)?;
    }

    if inventory.aspnet_handlers.is_empty() {
        writers::write_text(
            &layout.aspnet_handlers,
            "component_id,site_name,app_pool,component_type,name,path,verb,resource_type,source_config,mtime,sha256,risk_flags,confidence\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.aspnet_handlers, &inventory.aspnet_handlers)?;
    }

    if inventory.warnings.is_empty() {
        writers::write_text(
            &layout.runtime_warnings,
            "timestamp,target,path,message,evidence_gap,detail\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.runtime_warnings, &inventory.warnings)?;
    }

    if inventory.diffs.is_empty() {
        writers::write_text(
            &layout.component_diff,
            "component_id,component_type,name,path,change_type,baseline_path,current_hash,baseline_hash,risk_flags\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.component_diff, &inventory.diffs)?;
    }
    Ok(())
}

fn apply_baseline(baseline: &BaselineIndex, inventory: &mut RuntimeInventory) {
    if baseline.path.is_none() || (baseline.hashes.is_empty() && baseline.keys.is_empty()) {
        return;
    }
    let baseline_path = baseline.path.clone().unwrap_or_default();

    for row in &mut inventory.java_components {
        let key = row_key(
            &row.component_type,
            &row.name,
            &row.class_name,
            &row.source_path,
        );
        if baseline.is_new(&row.sha256, &key) {
            row.is_baseline_new = true;
            row.risk_flags = append_flag(&row.risk_flags, "baseline_new");
            row.confidence = confidence_for_flags(&row.risk_flags);
            inventory.diffs.push(ComponentDiffRow {
                component_id: row.component_id.clone(),
                component_type: row.component_type.clone(),
                name: row.name.clone(),
                path: row.source_path.clone(),
                change_type: "new_component".to_string(),
                baseline_path: baseline_path.clone(),
                current_hash: row.sha256.clone(),
                baseline_hash: String::new(),
                risk_flags: row.risk_flags.clone(),
            });
        }
    }

    for row in &mut inventory.tomcat_components {
        let key = row_key(
            &row.component_type,
            &row.name,
            &row.class_name,
            &row.source_path,
        );
        if baseline.is_new(&row.sha256, &key) {
            row.is_baseline_new = true;
            row.risk_flags = append_flag(&row.risk_flags, "baseline_new");
            row.confidence = confidence_for_flags(&row.risk_flags);
            inventory.diffs.push(ComponentDiffRow {
                component_id: row.component_id.clone(),
                component_type: row.component_type.clone(),
                name: row.name.clone(),
                path: row.source_path.clone(),
                change_type: "new_component".to_string(),
                baseline_path: baseline_path.clone(),
                current_hash: row.sha256.clone(),
                baseline_hash: String::new(),
                risk_flags: row.risk_flags.clone(),
            });
        }
    }

    for row in &mut inventory.spring_mappings {
        let key = row_key(
            &row.component_type,
            &row.route,
            &row.class_name,
            &row.jar_path,
        );
        if baseline.is_new(&row.sha256, &key) {
            row.risk_flags = append_flag(&row.risk_flags, "baseline_new");
            row.confidence = confidence_for_flags(&row.risk_flags);
            inventory.diffs.push(ComponentDiffRow {
                component_id: row.component_id.clone(),
                component_type: row.component_type.clone(),
                name: if row.route.is_empty() {
                    row.class_name.clone()
                } else {
                    row.route.clone()
                },
                path: row.jar_path.clone(),
                change_type: "new_component".to_string(),
                baseline_path: baseline_path.clone(),
                current_hash: row.sha256.clone(),
                baseline_hash: String::new(),
                risk_flags: row.risk_flags.clone(),
            });
        }
    }

    for row in &mut inventory.iis_modules {
        let key = row_key(&row.component_type, &row.name, &row.precondition, &row.path);
        if baseline.is_new(&row.sha256, &key) {
            row.is_baseline_new = true;
            row.risk_flags = append_flag(&row.risk_flags, "baseline_new");
            row.confidence = confidence_for_flags(&row.risk_flags);
            inventory.diffs.push(ComponentDiffRow {
                component_id: row.component_id.clone(),
                component_type: row.component_type.clone(),
                name: row.name.clone(),
                path: row.path.clone(),
                change_type: "new_component".to_string(),
                baseline_path: baseline_path.clone(),
                current_hash: row.sha256.clone(),
                baseline_hash: String::new(),
                risk_flags: row.risk_flags.clone(),
            });
        }
    }

    for row in &mut inventory.aspnet_handlers {
        let key = row_key(&row.component_type, &row.name, &row.verb, &row.path);
        if baseline.is_new(&row.sha256, &key) {
            row.risk_flags = append_flag(&row.risk_flags, "baseline_new");
            row.confidence = confidence_for_flags(&row.risk_flags);
            inventory.diffs.push(ComponentDiffRow {
                component_id: row.component_id.clone(),
                component_type: row.component_type.clone(),
                name: row.name.clone(),
                path: row.path.clone(),
                change_type: "new_component".to_string(),
                baseline_path: baseline_path.clone(),
                current_hash: row.sha256.clone(),
                baseline_hash: String::new(),
                risk_flags: row.risk_flags.clone(),
            });
        }
    }
}

impl BaselineIndex {
    fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let mut index = Self {
            path: Some(path.display().to_string()),
            ..Self::default()
        };
        if path.is_file() {
            index.read_csv(path)?;
        } else if path.is_dir() {
            for candidate in [
                path.join("runtime").join("java_components.csv"),
                path.join("runtime").join("tomcat_components.csv"),
                path.join("runtime").join("spring_mappings.csv"),
                path.join("runtime").join("iis_modules.csv"),
                path.join("runtime").join("aspnet_handlers.csv"),
                path.join("java_components.csv"),
                path.join("tomcat_components.csv"),
                path.join("spring_mappings.csv"),
                path.join("iis_modules.csv"),
                path.join("aspnet_handlers.csv"),
            ] {
                if candidate.is_file() {
                    index.read_csv(&candidate)?;
                }
            }
        }
        Ok(index)
    }

    fn read_csv(&mut self, path: &Path) -> Result<()> {
        let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path)?;
        let headers = reader
            .headers()?
            .iter()
            .map(normalize_header)
            .collect::<Vec<_>>();
        for record in reader.records().flatten() {
            let value_for = |name: &str| -> String {
                headers
                    .iter()
                    .position(|header| header == name)
                    .and_then(|index| record.get(index))
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            for hash_name in ["sha256", "current_hash", "baseline_hash"] {
                let hash = value_for(hash_name);
                if !hash.is_empty() {
                    self.hashes.insert(hash);
                }
            }
            let source_path = first_non_empty(&[
                value_for("source_path"),
                value_for("path"),
                value_for("jar_path"),
                value_for("source_config"),
            ]);
            let name = first_non_empty(&[value_for("name"), value_for("route")]);
            let class_name = first_non_empty(&[
                value_for("class_name"),
                value_for("precondition"),
                value_for("verb"),
                value_for("resource_type"),
            ]);
            let key = row_key(
                &value_for("component_type"),
                &name,
                &class_name,
                &source_path,
            );
            if key != "|||" {
                self.keys.insert(key);
            }
        }
        Ok(())
    }

    fn is_new(&self, sha256: &str, key: &str) -> bool {
        if !sha256.is_empty() && self.hashes.contains(sha256) {
            return false;
        }
        if self.keys.contains(key) {
            return false;
        }
        true
    }
}

fn append_flag(existing: &str, flag: &'static str) -> String {
    if existing.split(';').any(|value| value == flag) {
        existing.to_string()
    } else if existing.is_empty() {
        flag.to_string()
    } else {
        format!("{existing};{flag}")
    }
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
}

fn risk_flags_for_artifact(
    name: &str,
    class_name: &str,
    metadata: &ArtifactMetadata,
    extra_flags: &[&str],
) -> String {
    let mut flags = extra_flags.to_vec();
    if metadata.is_recent {
        flags.push("recent_change");
    }
    if suspicious_component_name(name) {
        flags.push("suspicious_name");
    }
    if suspicious_component_name(class_name) {
        flags.push("suspicious_class");
    }
    join_flags(flags)
}

fn row_key(component_type: &str, name: &str, class_name: &str, source_path: &str) -> String {
    format!(
        "{}|{}|{}|{}",
        component_type.trim().to_ascii_lowercase(),
        name.trim().to_ascii_lowercase(),
        class_name.trim().to_ascii_lowercase(),
        source_path.trim().to_ascii_lowercase()
    )
}

fn normalize_header(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn walk_files_inner(current: &Path, depth: usize, max_depth: usize, files: &mut Vec<PathBuf>) {
    if depth > max_depth || files.len() >= MAX_RUNTIME_FILES_PER_RUN {
        return;
    }
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= MAX_RUNTIME_FILES_PER_RUN {
            return;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk_files_inner(&path, depth + 1, max_depth, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

fn is_recent(modified: Option<SystemTime>, resolved: &ResolvedRun) -> bool {
    let Some(modified) = modified else {
        return false;
    };
    let Some(since) = resolved
        .time_range
        .since
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok())
    else {
        return false;
    };
    let since = if since.unix_timestamp() >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(since.unix_timestamp() as u64)
    } else {
        SystemTime::UNIX_EPOCH
    };
    modified >= since
}

fn system_time_to_iso(value: SystemTime) -> String {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
            else {
                return "unknown".to_string();
            };
            crate::time_utils::format_iso(datetime)
        }
        Err(_) => "unknown".to_string(),
    }
}

/// XML 实体解码：`&amp;` 必须最后替换，否则 `&amp;lt;` 会被先解成 `&lt;`
/// 再被解成 `<`（二次解码，原文义丢失）。
fn decode_xml_text(value: &str) -> String {
    value
        .trim()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
