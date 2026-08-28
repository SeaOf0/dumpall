use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use serde_yaml::Value as YamlValue;

use crate::collectors::container::{
    collect_log_file, optional_string, parse_error, record_seen_file, risk_flags_for_container,
    risk_flags_for_mount, ContainerInventory,
};
use crate::config::ResolvedRun;
use crate::model::{
    ContainerImageRecord, ContainerMountRecord, ContainerNetworkRecord, ContainerRecord,
};

pub const COLLECTOR_SCOPE: &str = "kubernetes_node";

pub(crate) fn collect_kubernetes_path(
    resolved: &ResolvedRun,
    path: &Path,
    inventory: &mut ContainerInventory,
) {
    if !path.exists() {
        inventory.errors.push(crate::collectors::collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "discover",
            "Kubernetes node path does not exist",
            Some("Verify the offline Kubernetes node-side path or pod log directory.".to_string()),
        ));
        return;
    }
    if path.is_file() {
        collect_kubernetes_file(resolved, path, inventory);
        return;
    }
    if !path.is_dir() {
        return;
    }
    for file in walk_files(path, resolved.safety.max_depth) {
        collect_kubernetes_file(resolved, &file, inventory);
    }
}

fn collect_kubernetes_file(
    resolved: &ResolvedRun,
    path: &Path,
    inventory: &mut ContainerInventory,
) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".yaml") || name.ends_with(".yml") {
        collect_manifest(path, inventory);
    } else if name.ends_with(".json") {
        if !collect_json_manifest(path, inventory) {
            collect_log_file(resolved, path, "kubernetes", inventory);
        }
    } else if name.ends_with(".log") || name.ends_with(".jsonl") || name.contains("kubelet") {
        collect_log_file(resolved, path, "kubernetes", inventory);
    }
}

fn collect_json_manifest(path: &Path, inventory: &mut ContainerInventory) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    if optional_string(&value, &["kind"]).is_none() && value.get("items").is_none() {
        return false;
    }
    record_seen_file(inventory);
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        for item in items {
            pod_from_json(item, path, inventory);
        }
    } else {
        pod_from_json(&value, path, inventory);
    }
    true
}

fn collect_manifest(path: &Path, inventory: &mut ContainerInventory) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    record_seen_file(inventory);
    // 多文档 YAML（--- 分隔）由 serde_yaml 反序列化器逐文档处理；
    // 单个文档解析失败记 parse error，不影响其余文档继续采集。
    // serde_yaml 的多文档迭代器在特定畸形输入（未闭合的 [ 或引号）上会
    // 无限产出错误文档且读取位置不前进——连续错误超阈值即判定解析器
    // 停滞，登记说明后终止该文件，绝不能让一个坏 manifest 挂死采集。
    const MAX_CONSECUTIVE_PARSE_ERRORS: u32 = 50;
    let mut consecutive_errors = 0u32;
    for (document_index, document) in serde_yaml::Deserializer::from_str(&text).enumerate() {
        let line_number = (document_index + 1) as u64;
        match YamlValue::deserialize(document) {
            Ok(value) => {
                consecutive_errors = 0;
                collect_manifest_document(&value, path, inventory);
            }
            Err(error) => {
                consecutive_errors += 1;
                inventory.parse_errors.push(parse_error(
                    path,
                    line_number,
                    "kubernetes_yaml",
                    format!("YAML document could not be parsed structurally: {error}"),
                    "",
                    false,
                ));
                if consecutive_errors >= MAX_CONSECUTIVE_PARSE_ERRORS {
                    inventory.parse_errors.push(parse_error(
                        path,
                        line_number,
                        "kubernetes_yaml",
                        "parser stalled on repeated malformed documents; remaining content of this file was skipped",
                        "",
                        false,
                    ));
                    return;
                }
            }
        }
    }
}

/// 结构化导航单个 manifest 文档：metadata.name/metadata.namespace/spec.nodeName/
/// containers[].name/privileged、volumes[].hostPath.path 与 volumeMounts 按 name 配对。
/// 非 Pod 文档（无 containers 结构）跳过；声明为 Pod 但结构不符时记 parse error，
/// 不再用全文第一个同名 key 猜值。
fn collect_manifest_document(value: &YamlValue, path: &Path, inventory: &mut ContainerInventory) {
    let kind = yaml_str(value, "kind");
    let declared_pod = kind.as_deref() == Some("Pod");

    let Some(metadata) = value.get("metadata") else {
        if declared_pod {
            push_manifest_structure_error(path, inventory, "Pod document has no metadata mapping");
        }
        return;
    };
    let namespace = yaml_str(metadata, "namespace");
    let pod_name = yaml_str(metadata, "name");
    let created_at = yaml_str(metadata, "creationTimestamp");

    // Pod 的 containers 在 spec 下；Deployment/StatefulSet 等在 spec.template.spec 下。
    let top_spec = value.get("spec");
    let pod_spec = match top_spec {
        Some(spec) if spec.get("containers").and_then(YamlValue::as_sequence).is_some() => spec,
        Some(spec) => match spec.get("template").and_then(|template| template.get("spec")) {
            Some(template_spec)
                if template_spec
                    .get("containers")
                    .and_then(YamlValue::as_sequence)
                    .is_some() =>
            {
                template_spec
            }
            _ => {
                if declared_pod {
                    push_manifest_structure_error(
                        path,
                        inventory,
                        "Pod document has no spec.containers sequence",
                    );
                }
                return;
            }
        },
        None => {
            if declared_pod {
                push_manifest_structure_error(path, inventory, "Pod document has no spec mapping");
            }
            return;
        }
    };

    let host_pid = yaml_bool_at(pod_spec, "hostPID");
    let host_network = yaml_bool_at(pod_spec, "hostNetwork");
    let node_name = yaml_str(pod_spec, "nodeName");
    let Some(containers) = pod_spec.get("containers").and_then(YamlValue::as_sequence)
    else {
        return;
    };

    // volumes[].name → hostPath.path（仅 hostPath 卷产生宿主机挂载证据）。
    let host_path_volumes: Vec<(String, String)> = pod_spec
        .get("volumes")
        .and_then(YamlValue::as_sequence)
        .map(|volumes| {
            volumes
                .iter()
                .filter_map(|volume| {
                    let name = yaml_str(volume, "name")?;
                    let host_path = volume.get("hostPath")?;
                    let source = yaml_str(host_path, "path")?;
                    Some((name, source))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut privileged_containers: Vec<String> = Vec::new();
    let mut mounted_volume_names: Vec<String> = Vec::new();
    let namespace_value = namespace.clone().unwrap_or_else(|| "default".to_string());
    let pod_label = pod_name.clone().unwrap_or_default();

    for container in containers {
        let container_name = yaml_str(container, "name").unwrap_or_default();
        let image = yaml_str(container, "image").unwrap_or_default();
        let privileged = container
            .get("securityContext")
            .map(|context| yaml_bool_at(context, "privileged"))
            .unwrap_or(false);
        if privileged {
            privileged_containers.push(container_name.clone());
        }
        let mut record = ContainerRecord {
            container_id: format!("k8s-{namespace_value}-{pod_label}-{container_name}"),
            container_name: container_name.clone(),
            runtime: "kubernetes".to_string(),
            image: image.clone(),
            image_id: String::new(),
            pod_name: pod_name.clone(),
            namespace: namespace.clone(),
            process_id: None,
            created_at: created_at.clone(),
            started_at: None,
            // 特权判定按容器自身的 securityContext.privileged，
            // 不再用整份文本 contains("privileged: true") 猜测。
            is_privileged: privileged,
            host_pid,
            host_network,
            risk_flags: String::new(),
            source_file: path.display().to_string(),
        };
        record.risk_flags = risk_flags_for_container(&record);
        // 调度节点名以结构化 flag 保留（k8s 节点侧取证定位多节点离线包时有用）。
        if let Some(node_name) = node_name.as_deref() {
            if record.risk_flags.is_empty() {
                record.risk_flags = format!("node:{node_name}");
            } else {
                record.risk_flags.push_str(&format!(";node:{node_name}"));
            }
        }

        // volumeMounts 与 volumes 按 name 配对（不再按出现序号硬配）。
        if let Some(mounts) = container.get("volumeMounts").and_then(YamlValue::as_sequence) {
            for mount in mounts {
                let Some(volume_name) = yaml_str(mount, "name") else {
                    continue;
                };
                let Some((_, source)) =
                    host_path_volumes.iter().find(|(name, _)| *name == volume_name)
                else {
                    continue;
                };
                mounted_volume_names.push(volume_name);
                let destination = yaml_str(mount, "mountPath")
                    .unwrap_or_else(|| source.clone());
                let risk_flags = risk_flags_for_mount(source, &destination, "rw");
                inventory.mounts.push(ContainerMountRecord {
                    container_id: record.container_id.clone(),
                    container_name: record.container_name.clone(),
                    source: source.clone(),
                    destination,
                    mode: "rw".to_string(),
                    is_sensitive: risk_flags.contains("sensitive_mount"),
                    risk_flags,
                });
            }
        }

        if record.host_network {
            inventory.networks.push(ContainerNetworkRecord {
                container_id: record.container_id.clone(),
                container_name: record.container_name.clone(),
                network: "host".to_string(),
                ip_address: String::new(),
                ports: String::new(),
                host_network: true,
                risk_flags: "host_network".to_string(),
            });
        }
        if !record.image.is_empty() {
            inventory.images.push(ContainerImageRecord {
                image: record.image.clone(),
                image_id: String::new(),
                created_at: record.created_at.clone(),
                size: None,
                repo_tags: vec![record.image.clone()],
                digest: None,
            });
        }
        inventory.containers.push(record);
    }

    // 整 Pod 特权标注：任一容器特权时在 Pod 的所有容器行上列明特权容器名，
    // 替代旧版全文 contains("privileged: true") 的猜测式判定。
    if !privileged_containers.is_empty() {
        let flag = format!(
            "pod_privileged_containers={}",
            privileged_containers.join(",")
        );
        let pushed = containers.len();
        for record in inventory.containers.iter_mut().rev().take(pushed) {
            if record.risk_flags.is_empty() {
                record.risk_flags = flag.clone();
            } else {
                record.risk_flags.push_str(&format!(";{flag}"));
            }
        }
    }

    // 声明了 hostPath 卷但没有任何容器挂载：仍保留宿主机路径证据。
    for (volume_name, source) in &host_path_volumes {
        if mounted_volume_names.contains(volume_name) {
            continue;
        }
        let risk_flags = risk_flags_for_mount(source, source, "rw");
        inventory.mounts.push(ContainerMountRecord {
            container_id: format!("k8s-{namespace_value}-{pod_label}"),
            container_name: pod_label.clone(),
            source: source.clone(),
            destination: source.clone(),
            mode: "rw".to_string(),
            is_sensitive: risk_flags.contains("sensitive_mount"),
            risk_flags,
        });
    }
}

fn push_manifest_structure_error(path: &Path, inventory: &mut ContainerInventory, message: &str) {
    inventory.parse_errors.push(parse_error(
        path,
        0,
        "kubernetes_yaml",
        message,
        "",
        false,
    ));
}

fn yaml_str(value: &YamlValue, key: &str) -> Option<String> {
    match value.get(key) {
        Some(YamlValue::String(text)) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Some(YamlValue::Number(number)) => Some(number.to_string()),
        _ => None,
    }
}

fn yaml_bool_at(value: &YamlValue, key: &str) -> bool {
    match value.get(key) {
        Some(YamlValue::Bool(flag)) => *flag,
        Some(YamlValue::String(text)) => text.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn pod_from_json(value: &Value, path: &Path, inventory: &mut ContainerInventory) {
    if optional_string(value, &["kind"]).as_deref() != Some("Pod")
        && value
            .get("spec")
            .and_then(|spec| spec.get("containers"))
            .is_none()
    {
        return;
    }
    let namespace = optional_string(value, &["metadata", "namespace"]);
    let pod_name = optional_string(value, &["metadata", "name"]);
    let host_pid = crate::collectors::container::bool_value(value, &["spec", "hostPID"]);
    let host_network = crate::collectors::container::bool_value(value, &["spec", "hostNetwork"]);
    let Some(containers) = value
        .get("spec")
        .and_then(|spec| spec.get("containers"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for container in containers {
        let container_name = optional_string(container, &["name"]).unwrap_or_default();
        let image = optional_string(container, &["image"]).unwrap_or_default();
        let privileged =
            crate::collectors::container::bool_value(container, &["securityContext", "privileged"]);
        let mut record = ContainerRecord {
            container_id: format!(
                "k8s-{}-{}-{}",
                namespace.clone().unwrap_or_else(|| "default".to_string()),
                pod_name.clone().unwrap_or_default(),
                container_name
            ),
            container_name,
            runtime: "kubernetes".to_string(),
            image,
            image_id: String::new(),
            pod_name: pod_name.clone(),
            namespace: namespace.clone(),
            process_id: None,
            created_at: optional_string(value, &["metadata", "creationTimestamp"]),
            started_at: None,
            is_privileged: privileged,
            host_pid,
            host_network,
            risk_flags: String::new(),
            source_file: path.display().to_string(),
        };
        record.risk_flags = risk_flags_for_container(&record);
        inventory.containers.push(record.clone());
        if !record.image.is_empty() {
            inventory.images.push(ContainerImageRecord {
                image: record.image.clone(),
                image_id: String::new(),
                created_at: record.created_at.clone(),
                size: None,
                repo_tags: vec![record.image.clone()],
                digest: None,
            });
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_yaml(text: &str) -> ContainerInventory {
        let root = crate::unique_test_dir("k8s-manifest");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("manifest.yaml");
        fs::write(&path, text).unwrap();
        let mut inventory = ContainerInventory::default();
        collect_manifest(&path, &mut inventory);
        fs::remove_dir_all(root).unwrap();
        inventory
    }

    const MULTI_DOC_POD: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-a-pod
data:
  key: value
---
apiVersion: v1
kind: Pod
metadata:
  name: edge-pod
  namespace: production
  creationTimestamp: "2026-05-15T08:00:00Z"
spec:
  hostPID: true
  hostNetwork: true
  nodeName: worker-3
  containers:
    - name: edge
      image: registry.local/edge:latest
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-etc
          mountPath: /host/etc
    - name: sidecar
      image: registry.local/log:1.0
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
  volumes:
    - name: host-etc
      hostPath:
        path: /etc
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
"#;

    #[test]
    fn multi_document_yaml_navigates_structurally() {
        let inventory = collect_yaml(MULTI_DOC_POD);

        // ConfigMap 文档跳过；Pod 每容器一行，字段按结构导航取值。
        assert_eq!(inventory.containers.len(), 2);
        let edge = inventory
            .containers
            .iter()
            .find(|record| record.container_name == "edge")
            .expect("edge container row");
        assert_eq!(edge.pod_name.as_deref(), Some("edge-pod"));
        assert_eq!(edge.namespace.as_deref(), Some("production"));
        assert_eq!(edge.image, "registry.local/edge:latest");
        assert!(edge.is_privileged);
        assert!(edge.host_pid);
        assert!(edge.host_network);
        assert!(edge.risk_flags.contains("node:worker-3"));
        assert!(edge.risk_flags.contains("pod_privileged_containers=edge"));

        let sidecar = inventory
            .containers
            .iter()
            .find(|record| record.container_name == "sidecar")
            .expect("sidecar container row");
        // sidecar 自身非特权，但 Pod 级标注列明特权容器名。
        assert!(!sidecar.is_privileged);
        assert!(sidecar.risk_flags.contains("pod_privileged_containers=edge"));
        assert_eq!(
            sidecar.created_at.as_deref(),
            Some("2026-05-15T08:00:00Z")
        );
    }

    #[test]
    fn volume_mounts_pair_by_name_not_order() {
        let inventory = collect_yaml(MULTI_DOC_POD);
        // 挂载按 volumeMounts.name ↔ volumes.name 配对：
        // sidecar(第二个容器)挂 docker-sock，不能按序号错配到 /etc。
        let sock_mount = inventory
            .mounts
            .iter()
            .find(|mount| mount.source == "/var/run/docker.sock")
            .expect("docker.sock mount");
        assert_eq!(sock_mount.destination, "/var/run/docker.sock");
        assert_eq!(sock_mount.container_name, "sidecar");

        let etc_mount = inventory
            .mounts
            .iter()
            .find(|mount| mount.source == "/etc")
            .expect("host /etc mount");
        assert_eq!(etc_mount.destination, "/host/etc");
        assert_eq!(etc_mount.container_name, "edge");
        assert!(etc_mount.risk_flags.contains("sensitive_mount"));
    }

    #[test]
    fn unparsable_document_records_parse_error() {
        let inventory = collect_yaml("kind: Pod\nmetadata: [broken\n");
        assert!(inventory.containers.is_empty());
        assert!(inventory
            .parse_errors
            .iter()
            .any(|error| error.parser_name == "kubernetes_yaml"));
    }

    #[test]
    fn pod_without_containers_structure_is_reported() {
        let inventory = collect_yaml("kind: Pod\nmetadata:\n  name: broken-pod\nspec:\n  hostPID: true\n");
        assert!(inventory.containers.is_empty());
        assert!(inventory
            .parse_errors
            .iter()
            .any(|error| error
                .message
                .contains("Pod document has no spec.containers sequence")));
    }
}
