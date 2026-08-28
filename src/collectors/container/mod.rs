use crate::collector_trait::{
    path_strings, CollectOutput, CollectPlan, Collector, Discovery, ResourceBudget,
};
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{
    CollectionError, ContainerImageRecord, ContainerLogEvent, ContainerMountRecord,
    ContainerNetworkRecord, ContainerRecord, ParseError,
};
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub mod containerd;
pub mod docker;
pub mod kubernetes;

pub struct ContainerCollector;

impl Collector for ContainerCollector {
    fn name(&self) -> &'static str {
        "container"
    }

    fn discover(&self, ctx: &ResolvedRun) -> Result<Vec<Discovery>> {
        let mut rows = Vec::new();
        for path in &ctx.container_log_paths {
            rows.push(Discovery {
                collector: self.name().to_string(),
                kind: "container_log".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "user supplied --container-log-path".to_string(),
            });
        }
        for path in &ctx.k8s_node_paths {
            rows.push(Discovery {
                collector: self.name().to_string(),
                kind: "kubernetes_node_path".to_string(),
                path: Some(path.display().to_string()),
                source: "cli".to_string(),
                evidence: "user supplied --k8s-node-path".to_string(),
            });
        }
        Ok(rows)
    }

    fn plan(&self, ctx: &ResolvedRun, discoveries: &[Discovery]) -> Result<CollectPlan> {
        let mut inputs = discoveries
            .iter()
            .filter_map(|discovery| discovery.path.clone())
            .collect::<Vec<_>>();
        if inputs.is_empty() && ctx.container_enabled() {
            inputs.push(format!(
                "{} runtime metadata and node-side logs",
                ctx.container_runtime.as_str()
            ));
        }

        Ok(CollectPlan {
            collector: self.name().to_string(),
            enabled: ctx.container_enabled(),
            readonly: true,
            dry_run_supported: true,
            active_check_allowed: false,
            summary: if ctx.container_enabled() {
                "Plan Docker/containerd/Kubernetes node-side evidence without entering containers or mutating runtime state.".to_string()
            } else {
                "Container collector disabled for this profile.".to_string()
            },
            inputs,
            outputs: vec![
                "containers/containers.csv".to_string(),
                "containers/images.csv".to_string(),
                "containers/mounts.csv".to_string(),
                "containers/container_network.csv".to_string(),
                "containers/container_logs.jsonl".to_string(),
                "containers/container_findings.csv".to_string(),
            ],
            budget: ResourceBudget {
                max_files: None,
                max_records: Some(ctx.max_event_records),
                max_file_size_mb: Some(ctx.safety.max_file_size_mb),
                active_check_allowed: false,
            },
        })
    }

    fn collect(&self, _ctx: &ResolvedRun, plan: &CollectPlan) -> Result<CollectOutput> {
        Ok(CollectOutput {
            collector: self.name().to_string(),
            files_scanned: 0,
            records_emitted: 0,
            notes: vec![format!(
                "{} is planned for implementation; M0 only establishes the collector contract.",
                plan.collector
            )],
            errors: Vec::new(),
        })
    }
}

pub fn manual_inputs(ctx: &ResolvedRun) -> Vec<String> {
    let mut paths = Vec::new();
    paths.extend(path_strings(&ctx.container_log_paths));
    paths.extend(path_strings(&ctx.k8s_node_paths));
    paths
}

#[derive(Debug, Default)]
pub struct ContainerCollectionReport {
    pub files_scanned: u64,
    pub records_emitted: u64,
    pub lines_seen: u64,
    pub errors: Vec<CollectionError>,
    pub parse_errors: Vec<ParseError>,
    pub notes: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ContainerInventory {
    pub containers: Vec<ContainerRecord>,
    pub images: Vec<ContainerImageRecord>,
    pub mounts: Vec<ContainerMountRecord>,
    pub networks: Vec<ContainerNetworkRecord>,
    pub logs: Vec<ContainerLogEvent>,
    pub errors: Vec<CollectionError>,
    pub parse_errors: Vec<ParseError>,
    pub files_scanned: u64,
    pub lines_seen: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ContainerRow {
    container_id: String,
    container_name: String,
    image: String,
    image_id: String,
    pod_name: String,
    namespace: String,
    process_id: String,
    created_at: String,
    started_at: String,
    is_privileged: bool,
    host_pid: bool,
    host_network: bool,
    risk_flags: String,
}

#[derive(Debug, Clone, Serialize)]
struct ImageRow {
    image: String,
    image_id: String,
    created_at: String,
    size: String,
    repo_tags: String,
    digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct MountRow {
    container_id: String,
    container_name: String,
    source: String,
    destination: String,
    mode: String,
    is_sensitive: bool,
    risk_flags: String,
}

#[derive(Debug, Clone, Serialize)]
struct NetworkRow {
    container_id: String,
    container_name: String,
    network: String,
    ip_address: String,
    ports: String,
    host_network: bool,
    risk_flags: String,
}

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<ContainerCollectionReport> {
    logger.log("collector: container node-side metadata and logs")?;
    let mut inventory = ContainerInventory::default();
    if resolved.container_log_paths.is_empty() && resolved.k8s_node_paths.is_empty() {
        // triage 模式由自动发现兜底（docker socket/containerd 元数据），
        // 不以"用户未显式供路径"为由记采集错误，避免淹没真实缺口。
        if resolved.mode != crate::model::RunMode::Triage {
            inventory.errors.push(crate::collectors::collection_error(
                "container",
                "container runtime sources",
                "discover",
                "container-ir profile was enabled but no container log or Kubernetes node path was supplied; container-side evidence was not collected in this milestone",
                Some("Provide --container-log-path or --k8s-node-path with offline runtime metadata/logs.".to_string()),
            ));
        }
    }

    for path in &resolved.container_log_paths {
        collect_container_path(resolved, path, &mut inventory);
    }
    for path in &resolved.k8s_node_paths {
        kubernetes::collect_kubernetes_path(resolved, path, &mut inventory);
    }

    dedupe_images(&mut inventory.images);
    write_inventory(layout, &inventory)?;
    let records_emitted = inventory.containers.len()
        + inventory.images.len()
        + inventory.mounts.len()
        + inventory.networks.len()
        + inventory.logs.len();
    Ok(ContainerCollectionReport {
        files_scanned: inventory.files_scanned,
        records_emitted: records_emitted as u64,
        lines_seen: inventory.lines_seen,
        errors: inventory.errors,
        parse_errors: inventory.parse_errors,
        notes: vec![format!(
            "container collection completed: {} container row(s), {} image row(s), {} mount row(s), {} network row(s), {} log event(s).",
            inventory.containers.len(),
            inventory.images.len(),
            inventory.mounts.len(),
            inventory.networks.len(),
            inventory.logs.len()
        )],
    })
}

fn collect_container_path(resolved: &ResolvedRun, path: &Path, inventory: &mut ContainerInventory) {
    if !path.exists() {
        inventory.errors.push(crate::collectors::collection_error(
            "container",
            path.display().to_string(),
            "discover",
            "container log path does not exist",
            Some("Verify the offline Docker/containerd metadata or log path.".to_string()),
        ));
        return;
    }
    if path.is_file() {
        collect_file(resolved, path, "container", inventory);
        return;
    }
    if !path.is_dir() {
        return;
    }
    for file in walk_files(path, resolved.safety.max_depth) {
        collect_file(resolved, &file, runtime_from_path(&file), inventory);
    }
}

fn collect_file(
    resolved: &ResolvedRun,
    path: &Path,
    runtime_hint: &str,
    inventory: &mut ContainerInventory,
) {
    if exceeds_limit(path, resolved) {
        inventory.errors.push(crate::collectors::collection_error(
            "container",
            path.display().to_string(),
            "preflight",
            "container file exceeds max-file-size limit",
            None,
        ));
        return;
    }
    let name = lower_name(path);
    if is_docker_config(path) {
        docker::collect_docker_config(path, inventory);
    } else if is_docker_image_metadata(path) {
        docker::collect_docker_image_metadata(path, inventory);
    } else if is_containerd_metadata(path) {
        containerd::collect_containerd_metadata(path, inventory);
    } else if is_probable_container_log(path) || name.ends_with(".log") || name.ends_with(".jsonl")
    {
        collect_log_file(resolved, path, runtime_hint, inventory);
    }
}

pub(crate) fn collect_log_file(
    resolved: &ResolvedRun,
    path: &Path,
    runtime: &str,
    inventory: &mut ContainerInventory,
) {
    let Ok(file) = fs::File::open(path) else {
        inventory.errors.push(crate::collectors::collection_error(
            "container",
            path.display().to_string(),
            "read",
            "could not read container log file",
            None,
        ));
        return;
    };
    inventory.files_scanned += 1;
    let mut reader = std::io::BufReader::new(file);
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    let mut line_number = 0u64;
    while (inventory.logs.len() as u64) < resolved.max_event_records {
        // read_until + lossy：非 UTF-8 日志行不再整行丢失，raw_hash 对行字节内容计算。
        let decoded =
            match crate::parsers::read_decoded_log_line(&mut reader, &mut buffer) {
                Ok(Some(decoded)) => decoded,
                Ok(None) => break,
                Err(_) => {
                    inventory.parse_errors.push(parse_error(
                        path,
                        line_number + 1,
                        "container_log",
                        "could not read container log line",
                        "",
                        resolved.safety.redact,
                    ));
                    break;
                }
            };
        line_number += 1;
        if decoded.text.trim().is_empty() {
            continue;
        }
        inventory.lines_seen += 1;
        match crate::parsers::container_log::parse_container_log_line(
            path,
            line_number,
            &decoded.text,
            runtime,
        ) {
            Ok(Some(mut event)) => {
                if resolved.safety.redact {
                    event.message_summary = crate::safety::redact_text(&event.message_summary);
                    event.container_name = event
                        .container_name
                        .map(|value| crate::safety::redact_text(&value));
                }
                if let Some(container_id) = container_id_from_log_path(path) {
                    event.container_id.get_or_insert(container_id);
                }
                inventory.logs.push(event);
            }
            Ok(None) => {}
            Err(message) => inventory.parse_errors.push(parse_error(
                path,
                line_number,
                "container_log",
                message,
                &decoded.text,
                resolved.safety.redact,
            )),
        }
    }
}

pub(crate) fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub(crate) fn record_seen_file(inventory: &mut ContainerInventory) {
    inventory.files_scanned += 1;
}

pub(crate) fn parse_error(
    path: &Path,
    line_number: u64,
    parser_name: &str,
    message: impl Into<String>,
    raw: &str,
    redact: bool,
) -> ParseError {
    ParseError {
        source_file: path.display().to_string(),
        line_number,
        parser_name: parser_name.to_string(),
        message: message.into(),
        raw_hash: crate::parsers::access_log::sha256_hex(raw.as_bytes()),
        raw_sample: (!raw.is_empty()).then(|| {
            let sample = raw.chars().take(200).collect::<String>();
            if redact {
                crate::safety::redact_text(&sample)
            } else {
                sample
            }
        }),
    }
}

pub(crate) fn risk_flags_for_container(record: &ContainerRecord) -> String {
    let mut flags = Vec::new();
    if record.is_privileged {
        flags.push("privileged");
    }
    if record.host_pid {
        flags.push("host_pid");
    }
    if record.host_network {
        flags.push("host_network");
    }
    join_flags(flags)
}

pub(crate) fn risk_flags_for_mount(source: &str, destination: &str, mode: &str) -> String {
    let mut flags = Vec::new();
    if sensitive_mount(source, destination) {
        flags.push("sensitive_mount");
    }
    if web_root_mount(destination) || web_root_mount(source) {
        flags.push("web_root_mount");
    }
    let lower_mode = mode.to_ascii_lowercase();
    if !lower_mode.contains("ro")
        && (sensitive_mount(source, destination) || web_root_mount(destination))
    {
        flags.push("writable_mount");
    }
    join_flags(flags)
}

pub(crate) fn sensitive_mount(source: &str, destination: &str) -> bool {
    let combined = format!("{source} {destination}")
        .replace('\\', "/")
        .to_ascii_lowercase();
    [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/proc",
        "/sys",
        "/etc",
        "/root",
        "/var/lib/docker",
        "/var/lib/kubelet",
        "/host",
    ]
    .iter()
    .any(|needle| combined.contains(needle))
}

pub(crate) fn web_root_mount(value: &str) -> bool {
    let lower = value.replace('\\', "/").to_ascii_lowercase();
    [
        "/var/www",
        "/usr/share/nginx/html",
        "/usr/local/tomcat/webapps",
        "/app/public",
        "/inetpub/wwwroot",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn join_flags(mut flags: Vec<&str>) -> String {
    flags.sort_unstable();
    flags.dedup();
    flags.join(";")
}

pub(crate) fn string_value(value: &serde_json::Value, path: &[&str]) -> String {
    let mut current = value;
    for part in path {
        let Some(next) = current.get(*part) else {
            return String::new();
        };
        current = next;
    }
    scalar_to_string(current)
}

pub(crate) fn optional_string(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let value = string_value(value, path);
    (!value.is_empty()).then_some(value)
}

pub(crate) fn scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.trim().to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        _ => String::new(),
    }
}

pub(crate) fn bool_value(value: &serde_json::Value, path: &[&str]) -> bool {
    let mut current = value;
    for part in path {
        let Some(next) = current.get(*part) else {
            return false;
        };
        current = next;
    }
    match current {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::String(text) => text.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn write_inventory(layout: &OutputLayout, inventory: &ContainerInventory) -> Result<()> {
    let container_rows = inventory
        .containers
        .iter()
        .map(|row| ContainerRow {
            container_id: row.container_id.clone(),
            container_name: row.container_name.clone(),
            image: row.image.clone(),
            image_id: row.image_id.clone(),
            pod_name: row.pod_name.clone().unwrap_or_default(),
            namespace: row.namespace.clone().unwrap_or_default(),
            process_id: row.process_id.clone().unwrap_or_default(),
            created_at: row.created_at.clone().unwrap_or_default(),
            started_at: row.started_at.clone().unwrap_or_default(),
            is_privileged: row.is_privileged,
            host_pid: row.host_pid,
            host_network: row.host_network,
            risk_flags: row.risk_flags.clone(),
        })
        .collect::<Vec<_>>();
    if container_rows.is_empty() {
        writers::write_text(
            &layout.containers,
            "container_id,container_name,image,image_id,pod_name,namespace,process_id,created_at,started_at,is_privileged,host_pid,host_network,risk_flags\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.containers, &container_rows)?;
    }

    let image_rows = inventory
        .images
        .iter()
        .map(|row| ImageRow {
            image: row.image.clone(),
            image_id: row.image_id.clone(),
            created_at: row.created_at.clone().unwrap_or_default(),
            size: row.size.map(|value| value.to_string()).unwrap_or_default(),
            repo_tags: row.repo_tags.join(";"),
            digest: row.digest.clone().unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    if image_rows.is_empty() {
        writers::write_text(
            &layout.images,
            "image,image_id,created_at,size,repo_tags,digest\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.images, &image_rows)?;
    }

    let mount_rows = inventory
        .mounts
        .iter()
        .map(|row| MountRow {
            container_id: row.container_id.clone(),
            container_name: row.container_name.clone(),
            source: row.source.clone(),
            destination: row.destination.clone(),
            mode: row.mode.clone(),
            is_sensitive: row.is_sensitive,
            risk_flags: row.risk_flags.clone(),
        })
        .collect::<Vec<_>>();
    if mount_rows.is_empty() {
        writers::write_text(
            &layout.mounts,
            "container_id,container_name,source,destination,mode,is_sensitive,risk_flags\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.mounts, &mount_rows)?;
    }

    let network_rows = inventory
        .networks
        .iter()
        .map(|row| NetworkRow {
            container_id: row.container_id.clone(),
            container_name: row.container_name.clone(),
            network: row.network.clone(),
            ip_address: row.ip_address.clone(),
            ports: row.ports.clone(),
            host_network: row.host_network,
            risk_flags: row.risk_flags.clone(),
        })
        .collect::<Vec<_>>();
    if network_rows.is_empty() {
        writers::write_text(
            &layout.container_network,
            "container_id,container_name,network,ip_address,ports,host_network,risk_flags\n",
        )?;
    } else {
        writers::write_csv_serialize(&layout.container_network, &network_rows)?;
    }

    writers::write_container_logs_jsonl(&layout.container_logs, &inventory.logs)?;
    Ok(())
}

fn walk_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, 0, max_depth, &mut files);
    files
}

fn walk(path: &Path, depth: usize, max_depth: usize, files: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&child, depth + 1, max_depth, files);
        } else if file_type.is_file() {
            files.push(child);
        }
    }
}

fn exceeds_limit(path: &Path, resolved: &ResolvedRun) -> bool {
    let max_bytes = resolved.safety.max_file_size_mb.saturating_mul(1024 * 1024);
    fs::metadata(path)
        .map(|metadata| metadata.len() > max_bytes)
        .unwrap_or(false)
}

fn is_docker_config(path: &Path) -> bool {
    lower_name(path) == "config.v2.json"
}

fn is_docker_image_metadata(path: &Path) -> bool {
    let name = lower_name(path);
    name == "repositories.json" || name == "image.json" || name == "manifest.json"
}

fn is_containerd_metadata(path: &Path) -> bool {
    let name = lower_name(path);
    name.ends_with(".json")
        && (name.contains("containerd") || path.display().to_string().contains("io.containerd"))
}

fn is_probable_container_log(path: &Path) -> bool {
    let name = lower_name(path);
    name.ends_with("-json.log")
        || name.contains("container")
        || name.contains("pod")
        || name.contains("kubelet")
}

fn runtime_from_path(path: &Path) -> &str {
    let path_text = path.display().to_string().to_ascii_lowercase();
    if path_text.contains("containerd") {
        "containerd"
    } else if path_text.contains("kubernetes")
        || path_text.contains("pods")
        || path_text.contains("kubelet")
    {
        "kubernetes"
    } else {
        "docker"
    }
}

fn lower_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn container_id_from_log_path(path: &Path) -> Option<String> {
    let stem = path.file_name()?.to_str()?;
    if let Some((prefix, _)) = stem.split_once("-json.log") {
        return Some(prefix.to_string()).filter(|value| !value.is_empty());
    }
    None
}

fn dedupe_images(images: &mut Vec<ContainerImageRecord>) {
    let mut seen = BTreeMap::new();
    images.retain(|image| {
        let key = format!("{}|{}", image.image, image.image_id);
        if let std::collections::btree_map::Entry::Vacant(entry) = seen.entry(key) {
            entry.insert(true);
            true
        } else {
            false
        }
    });
}
