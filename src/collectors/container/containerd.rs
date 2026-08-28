use std::path::Path;

use serde_json::Value;

use crate::collectors::container::{
    bool_value, optional_string, read_json, record_seen_file, risk_flags_for_container,
    risk_flags_for_mount, ContainerInventory,
};
use crate::model::{
    ContainerImageRecord, ContainerMountRecord, ContainerNetworkRecord, ContainerRecord,
};

pub const COLLECTOR_SCOPE: &str = "containerd";

pub(crate) fn collect_containerd_metadata(path: &Path, inventory: &mut ContainerInventory) {
    let Some(value) = read_json(path) else {
        return;
    };
    record_seen_file(inventory);
    if let Some(containers) = value.get("containers").and_then(Value::as_array) {
        for container in containers {
            push_container(path, container, inventory);
        }
        return;
    }
    if looks_like_containerd_container(&value) {
        push_container(path, &value, inventory);
    }
}

fn push_container(path: &Path, value: &Value, inventory: &mut ContainerInventory) {
    let mut record = ContainerRecord {
        container_id: optional_string(value, &["id"])
            .or_else(|| optional_string(value, &["ID"]))
            .or_else(|| optional_string(value, &["metadata", "id"]))
            .unwrap_or_default(),
        container_name: optional_string(value, &["name"])
            .or_else(|| optional_string(value, &["metadata", "name"]))
            .unwrap_or_default(),
        runtime: "containerd".to_string(),
        image: optional_string(value, &["image"])
            .or_else(|| optional_string(value, &["Image"]))
            .or_else(|| optional_string(value, &["spec", "image"]))
            .unwrap_or_default(),
        image_id: optional_string(value, &["image_id"])
            .or_else(|| optional_string(value, &["imageID"]))
            .unwrap_or_default(),
        pod_name: optional_string(value, &["labels", "io.kubernetes.pod.name"]),
        namespace: optional_string(value, &["labels", "io.kubernetes.pod.namespace"]),
        process_id: optional_string(value, &["pid"]),
        created_at: optional_string(value, &["created_at"])
            .or_else(|| optional_string(value, &["createdAt"])),
        started_at: optional_string(value, &["started_at"])
            .or_else(|| optional_string(value, &["startedAt"])),
        is_privileged: bool_value(value, &["privileged"])
            || bool_value(value, &["spec", "linux", "security_context", "privileged"]),
        host_pid: bool_value(value, &["host_pid"]) || bool_value(value, &["hostPID"]),
        host_network: bool_value(value, &["host_network"]) || bool_value(value, &["hostNetwork"]),
        risk_flags: String::new(),
        source_file: path.display().to_string(),
    };
    record.risk_flags = risk_flags_for_container(&record);
    for mount in mounts_from_value(&record, value) {
        inventory.mounts.push(mount);
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
    if !record.image.is_empty() || !record.image_id.is_empty() {
        let repo_tags = if !record.image.is_empty() {
            vec![record.image.clone()]
        } else {
            Vec::new()
        };
        inventory.images.push(ContainerImageRecord {
            image: record.image.clone(),
            image_id: record.image_id.clone(),
            created_at: record.created_at.clone(),
            size: None,
            repo_tags,
            digest: None,
        });
    }
    inventory.containers.push(record);
}

fn mounts_from_value(record: &ContainerRecord, value: &Value) -> Vec<ContainerMountRecord> {
    let mut rows = Vec::new();
    let arrays = [
        value.get("mounts"),
        value.get("Mounts"),
        value.get("spec").and_then(|spec| spec.get("mounts")),
    ];
    for array in arrays.into_iter().flatten().filter_map(Value::as_array) {
        for mount in array {
            let source = optional_string(mount, &["source"])
                .or_else(|| optional_string(mount, &["Source"]))
                .unwrap_or_default();
            let destination = optional_string(mount, &["destination"])
                .or_else(|| optional_string(mount, &["Destination"]))
                .or_else(|| optional_string(mount, &["containerPath"]))
                .unwrap_or_default();
            let mode = optional_string(mount, &["options"])
                .or_else(|| optional_string(mount, &["mode"]))
                .unwrap_or_default();
            let risk_flags = risk_flags_for_mount(&source, &destination, &mode);
            if source.is_empty() && destination.is_empty() {
                continue;
            }
            rows.push(ContainerMountRecord {
                container_id: record.container_id.clone(),
                container_name: record.container_name.clone(),
                source,
                destination,
                mode,
                is_sensitive: risk_flags.contains("sensitive_mount"),
                risk_flags,
            });
        }
    }
    rows
}

fn looks_like_containerd_container(value: &Value) -> bool {
    optional_string(value, &["id"]).is_some()
        || optional_string(value, &["metadata", "id"]).is_some()
        || optional_string(value, &["image"]).is_some()
}
