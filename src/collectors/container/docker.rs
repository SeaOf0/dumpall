use std::path::Path;

use serde_json::Value;

use crate::collectors::container::{
    bool_value, optional_string, read_json, record_seen_file, risk_flags_for_container,
    risk_flags_for_mount, scalar_to_string, string_value, ContainerInventory,
};
use crate::model::{
    ContainerImageRecord, ContainerMountRecord, ContainerNetworkRecord, ContainerRecord,
};

pub const COLLECTOR_SCOPE: &str = "docker";

pub(crate) fn collect_docker_config(path: &Path, inventory: &mut ContainerInventory) {
    let Some(value) = read_json(path) else {
        inventory
            .parse_errors
            .push(crate::collectors::container::parse_error(
                path,
                0,
                "docker_config",
                "invalid Docker config JSON",
                "",
                false,
            ));
        return;
    };
    record_seen_file(inventory);
    let mut record = container_record_from_config(path, &value);
    record.risk_flags = risk_flags_for_container(&record);
    for mount in mounts_from_config(&record, &value) {
        inventory.mounts.push(mount);
    }
    for network in networks_from_config(&record, &value) {
        inventory.networks.push(network);
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

pub(crate) fn collect_docker_image_metadata(path: &Path, inventory: &mut ContainerInventory) {
    let Some(value) = read_json(path) else {
        return;
    };
    record_seen_file(inventory);
    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(image) = image_from_value(&item) {
                    inventory.images.push(image);
                }
            }
        }
        Value::Object(_) => {
            if let Some(image) = image_from_value(&value) {
                inventory.images.push(image);
            }
        }
        _ => {}
    }
}

fn container_record_from_config(path: &Path, value: &Value) -> ContainerRecord {
    let name = optional_string(value, &["Name"])
        .or_else(|| optional_string(value, &["Config", "Hostname"]))
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    ContainerRecord {
        container_id: optional_string(value, &["ID"])
            .or_else(|| container_id_from_path(path))
            .unwrap_or_default(),
        container_name: name,
        runtime: "docker".to_string(),
        image: optional_string(value, &["Config", "Image"])
            .or_else(|| optional_string(value, &["ImageName"]))
            .unwrap_or_default(),
        image_id: optional_string(value, &["Image"]).unwrap_or_default(),
        pod_name: None,
        namespace: None,
        process_id: optional_string(value, &["State", "Pid"]),
        created_at: optional_string(value, &["Created"]),
        started_at: optional_string(value, &["State", "StartedAt"]),
        is_privileged: bool_value(value, &["HostConfig", "Privileged"]),
        host_pid: string_value(value, &["HostConfig", "PidMode"]).contains("host"),
        host_network: string_value(value, &["HostConfig", "NetworkMode"]).contains("host"),
        risk_flags: String::new(),
        source_file: path.display().to_string(),
    }
}

fn mounts_from_config(record: &ContainerRecord, value: &Value) -> Vec<ContainerMountRecord> {
    let mut mounts = Vec::new();
    if let Some(items) = value.get("MountPoints").and_then(Value::as_object) {
        for mount in items.values() {
            let source = optional_string(mount, &["Source"]).unwrap_or_default();
            let destination = optional_string(mount, &["Destination"])
                .or_else(|| optional_string(mount, &["DestinationPath"]))
                .unwrap_or_default();
            let mode = optional_string(mount, &["Mode"])
                .or_else(|| {
                    optional_string(mount, &["RW"])
                        .map(|rw| if rw == "true" { "rw" } else { "ro" }.to_string())
                })
                .unwrap_or_default();
            push_mount(record, &mut mounts, source, destination, mode);
        }
    }
    if let Some(items) = value.get("Mounts").and_then(Value::as_array) {
        for mount in items {
            let source = optional_string(mount, &["Source"]).unwrap_or_default();
            let destination = optional_string(mount, &["Destination"]).unwrap_or_default();
            let mode = optional_string(mount, &["Mode"]).unwrap_or_default();
            push_mount(record, &mut mounts, source, destination, mode);
        }
    }
    mounts
}

fn push_mount(
    record: &ContainerRecord,
    mounts: &mut Vec<ContainerMountRecord>,
    source: String,
    destination: String,
    mode: String,
) {
    if source.is_empty() && destination.is_empty() {
        return;
    }
    let risk_flags = risk_flags_for_mount(&source, &destination, &mode);
    mounts.push(ContainerMountRecord {
        container_id: record.container_id.clone(),
        container_name: record.container_name.clone(),
        source,
        destination,
        mode,
        is_sensitive: risk_flags.contains("sensitive_mount"),
        risk_flags,
    });
}

fn networks_from_config(record: &ContainerRecord, value: &Value) -> Vec<ContainerNetworkRecord> {
    let mut rows = Vec::new();
    if record.host_network {
        rows.push(ContainerNetworkRecord {
            container_id: record.container_id.clone(),
            container_name: record.container_name.clone(),
            network: "host".to_string(),
            ip_address: String::new(),
            ports: ports_from_config(value),
            host_network: true,
            risk_flags: "host_network".to_string(),
        });
    }
    if let Some(networks) = value
        .get("NetworkSettings")
        .and_then(|settings| settings.get("Networks"))
        .and_then(Value::as_object)
    {
        for (name, network) in networks {
            rows.push(ContainerNetworkRecord {
                container_id: record.container_id.clone(),
                container_name: record.container_name.clone(),
                network: name.clone(),
                ip_address: optional_string(network, &["IPAddress"]).unwrap_or_default(),
                ports: ports_from_config(value),
                host_network: false,
                risk_flags: String::new(),
            });
        }
    }
    rows
}

fn ports_from_config(value: &Value) -> String {
    let Some(ports) = value
        .get("NetworkSettings")
        .and_then(|settings| settings.get("Ports"))
        .and_then(Value::as_object)
    else {
        return String::new();
    };
    let mut rows = Vec::new();
    for (container_port, bindings) in ports {
        match bindings {
            Value::Array(items) => {
                for item in items {
                    let host_ip = optional_string(item, &["HostIp"]).unwrap_or_default();
                    let host_port = optional_string(item, &["HostPort"]).unwrap_or_default();
                    rows.push(format!("{host_ip}:{host_port}->{container_port}"));
                }
            }
            _ => rows.push(container_port.clone()),
        }
    }
    rows.join(";")
}

fn image_from_value(value: &Value) -> Option<ContainerImageRecord> {
    let image_id = optional_string(value, &["id"])
        .or_else(|| optional_string(value, &["Id"]))
        .or_else(|| optional_string(value, &["ID"]))
        .unwrap_or_default();
    let image = optional_string(value, &["RepoTags", "0"])
        .or_else(|| optional_string(value, &["image"]))
        .unwrap_or_default();
    if image_id.is_empty() && image.is_empty() {
        return None;
    }
    let repo_tags = value
        .get("RepoTags")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(scalar_to_string)
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Some(ContainerImageRecord {
        image,
        image_id,
        created_at: optional_string(value, &["created"])
            .or_else(|| optional_string(value, &["Created"])),
        size: optional_string(value, &["Size"]).and_then(|value| value.parse::<u64>().ok()),
        repo_tags,
        digest: optional_string(value, &["Digest"])
            .or_else(|| optional_string(value, &["RepoDigests", "0"])),
    })
}

fn container_id_from_path(path: &Path) -> Option<String> {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|value| value.to_str())
        .map(str::to_string)
}
