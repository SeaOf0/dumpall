//! 网络补充信息采集：ARP 缓存、Unix 域套接字、DNS/hosts/nsswitch 配置、
//! 防火墙规则（iptables-save / nft 只读导出，二进制存在才执行）。

use std::fs;
use std::process::Command;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const ARP_HEADER: &str = "ip_address,hw_type,flags,hw_address,mask,device\n";
const UNIX_HEADER: &str = "ref_count,type,state,socket_inode,path\n";
const DNS_HEADER: &str = "kind,source,key,value\n";
const FIREWALL_HEADER: &str = "tool,line\n";

#[derive(Debug, Clone, Serialize)]
struct ArpRow {
    ip_address: String,
    hw_type: String,
    flags: String,
    hw_address: String,
    mask: String,
    device: String,
}

#[derive(Debug, Clone, Serialize)]
struct UnixSocketRow {
    ref_count: String,
    r#type: String,
    state: String,
    socket_inode: String,
    path: String,
}

#[derive(Debug, Clone, Serialize)]
struct DnsConfigRow {
    kind: String,
    source: String,
    key: String,
    value: String,
}

#[derive(Debug, Clone, Serialize)]
struct FirewallRow {
    tool: String,
    line: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_arp(layout)?;
    collect_unix_sockets(layout)?;
    collect_dns(layout)?;
    collect_firewall(layout, errors)?;
    Ok(())
}

fn collect_arp(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 {
                rows.push(ArpRow {
                    ip_address: fields[0].to_string(),
                    hw_type: fields[1].to_string(),
                    flags: fields[2].to_string(),
                    hw_address: fields[3].to_string(),
                    mask: fields[4].to_string(),
                    device: fields[5].to_string(),
                });
            }
        }
    }
    write_rows(&layout.arp_cache, ARP_HEADER, &rows)
}

fn collect_unix_sockets(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 8 {
                let path = if fields.len() > 8 {
                    fields[8..].join(" ")
                } else {
                    String::new()
                };
                rows.push(UnixSocketRow {
                    ref_count: fields[4].to_string(),
                    r#type: fields[2].to_string(),
                    state: fields[5].to_string(),
                    socket_inode: fields[6].to_string(),
                    path,
                });
            }
        }
    }
    write_rows(&layout.unix_sockets, UNIX_HEADER, &rows)
}

fn collect_dns(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    append_kv_file(
        &mut rows,
        "nameserver",
        "/etc/resolv.conf",
        "",
        "nameserver",
    );
    append_kv_file(&mut rows, "search", "/etc/resolv.conf", "", "search");
    append_kv_file(&mut rows, "options", "/etc/resolv.conf", "", "options");
    append_kv_file(&mut rows, "hosts_entry", "/etc/hosts", "", "");
    append_kv_file(&mut rows, "nsswitch", "/etc/nsswitch.conf", "", "");
    write_rows(&layout.dns_config, DNS_HEADER, &rows)
}

fn append_kv_file(
    rows: &mut Vec<DnsConfigRow>,
    kind: &str,
    path: &str,
    _prefix: &str,
    _match_key: &str,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or("").to_string();
        let value = parts.next().unwrap_or("").trim().to_string();
        rows.push(DnsConfigRow {
            kind: kind.to_string(),
            source: path.to_string(),
            key,
            value,
        });
    }
}

fn collect_firewall(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let mut rows = Vec::new();
    for (tool, args) in [
        ("iptables-save", Vec::<&str>::new()),
        ("nft", vec!["list", "ruleset"]),
    ] {
        // 只读白名单命令：二进制存在于 PATH 才执行，失败降级记录。
        let Some(tool_path) = super::which(tool) else {
            continue;
        };
        match Command::new(tool_path).args(&args).output() {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    rows.push(FirewallRow {
                        tool: tool.to_string(),
                        line: line.trim().to_string(),
                    });
                }
            }
            Ok(output) => errors.push(super::collection_error(
                "firewall_rules",
                tool,
                "export_rules",
                "firewall rule export exited non-zero",
                Some(format!("status={}", output.status)),
            )),
            Err(error) => errors.push(super::collection_error(
                "firewall_rules",
                tool,
                "export_rules",
                "firewall rule export could not be executed",
                Some(error.to_string()),
            )),
        }
        if !rows.is_empty() {
            break;
        }
    }
    write_rows(&layout.firewall_rules, FIREWALL_HEADER, &rows)
}

fn write_rows<T: serde::Serialize>(path: &std::path::Path, header: &str, rows: &[T]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, header)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn which_finds_ls_on_unix_like_hosts() {
        // CI/开发机为 macOS/Linux；找不到也不失败（PATH 差异）。
        let found = crate::collectors::host_artifacts::which("ls").is_some()
            || crate::collectors::host_artifacts::which("sh").is_some();
        assert!(found);
    }
}
