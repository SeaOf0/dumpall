#[cfg(unix)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(unix)]
use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
#[cfg(unix)]
use crate::output::writers;

#[cfg(unix)]
use super::collection_error;
#[cfg(windows)]
use super::command::{collect_text_command, CommandSpec};

const NETWORK_HEADER: &str = "protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,remote_class\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public,
    Unspecified,
    Reserved,
    Invalid,
}

impl IpClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::Multicast => "multicast",
            Self::Public => "public",
            Self::Unspecified => "unspecified",
            Self::Reserved => "reserved",
            Self::Invalid => "invalid",
        }
    }
}

pub fn classify_ip(value: &str) -> IpClass {
    let trimmed = value.trim().trim_matches(['[', ']']);
    let Ok(ip) = trimmed.parse::<IpAddr>() else {
        return IpClass::Invalid;
    };

    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpClass {
    if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_private() {
        IpClass::Private
    } else if ip.is_link_local() {
        IpClass::LinkLocal
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.octets()[0] >= 240 {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> IpClass {
    if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        IpClass::Private
    } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        IpClass::LinkLocal
    } else {
        IpClass::Public
    }
}

pub fn collect(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = redact;
        collect_unix(layout, errors)
    }

    #[cfg(windows)]
    {
        collect_windows(layout, errors, redact)
    }
}

#[cfg(windows)]
fn collect_windows(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    collect_text_command(
        "network",
        &layout.network_connections,
        NETWORK_HEADER,
        &network_commands(),
        errors,
        redact,
    )
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct NetworkRow {
    protocol: String,
    local_address: String,
    local_port: String,
    remote_address: String,
    remote_port: String,
    state: String,
    pid: String,
    process_name: String,
    remote_class: String,
}

#[cfg(windows)]
fn network_commands() -> Vec<CommandSpec> {
    let script = r#"
 $processNames = @{}
 $processUsers = @{}
 try {
   Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
     $processId = [int]$_.ProcessId
     $processNames[$processId] = [string]$_.Name
     try {
       $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
       if ($owner.ReturnValue -eq 0 -and $owner.User) {
         $processUsers[$processId] = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { [string]$owner.User }
       }
     } catch {}
   }
 } catch {
   Write-Error ("process enumeration failed: " + $_.Exception.Message)
 }
function Get-RemoteClass($address) {
  if ([string]::IsNullOrWhiteSpace($address) -or $address -eq '0.0.0.0' -or $address -eq '::') { return 'unspecified' }
  if ($address -eq '127.0.0.1' -or $address -eq '::1') { return 'loopback' }
  if ($address -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') { return 'private' }
  if ($address -match '^169\.254\.') { return 'link_local' }
  return 'public_or_other'
}
$tcp = Get-NetTCPConnection -ErrorAction Stop |
  Select-Object @{Name='protocol';Expression={'tcp'}},
    @{Name='local_address';Expression={$_.LocalAddress}},
    @{Name='local_port';Expression={$_.LocalPort}},
    @{Name='remote_address';Expression={$_.RemoteAddress}},
    @{Name='remote_port';Expression={$_.RemotePort}},
    @{Name='state';Expression={$_.State}},
    @{Name='pid';Expression={$_.OwningProcess}},
    @{Name='process_name';Expression={ $processNames[[int]$_.OwningProcess] }},
    @{Name='remote_class';Expression={Get-RemoteClass $_.RemoteAddress}}
$udp = @(Get-NetUDPEndpoint -ErrorAction Stop) |
  Select-Object @{Name='protocol';Expression={'udp'}},
    @{Name='local_address';Expression={$_.LocalAddress}},
    @{Name='local_port';Expression={$_.LocalPort}},
    @{Name='remote_address';Expression={''}},
    @{Name='remote_port';Expression={''}},
    @{Name='state';Expression={''}},
    @{Name='pid';Expression={$_.OwningProcess}},
    @{Name='process_name';Expression={ $processNames[[int]$_.OwningProcess] }},
    @{Name='remote_class';Expression={''}}
@($tcp) + @($udp) | ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(unix)]
fn collect_unix(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let inode_processes = socket_inode_processes();
    let mut rows = Vec::new();
    for (path, protocol) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ] {
        collect_proc_net(path, protocol, &inode_processes, errors, &mut rows);
    }
    rows.sort_by(|left, right| {
        (
            left.protocol.as_str(),
            left.local_address.as_str(),
            left.local_port.as_str(),
            left.remote_address.as_str(),
            left.remote_port.as_str(),
        )
            .cmp(&(
                right.protocol.as_str(),
                right.local_address.as_str(),
                right.local_port.as_str(),
                right.remote_address.as_str(),
                right.remote_port.as_str(),
            ))
    });
    if rows.is_empty() {
        writers::write_text(&layout.network_connections, NETWORK_HEADER)
    } else {
        writers::write_csv_serialize(&layout.network_connections, &rows)
    }
}

#[cfg(unix)]
fn collect_proc_net(
    path: &str,
    protocol: &str,
    inode_processes: &BTreeMap<String, ProcessSocketOwner>,
    errors: &mut Vec<CollectionError>,
    rows: &mut Vec<NetworkRow>,
) {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            errors.push(collection_error(
                "network",
                path,
                "read_proc_net",
                "network socket table could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let (local_address, local_port) = decode_proc_address(fields[1]);
        let (remote_address, remote_port) = decode_proc_address(fields[2]);
        // /proc/net/udp 的 state 列(00/07)不是 TCP 语义,统一标注为 UDP,
        // 避免连接表里出现无意义的 "00"。
        let state = if protocol.eq_ignore_ascii_case("udp") {
            "UDP".to_string()
        } else {
            tcp_state(fields[3])
        };
        let inode = fields[9];
        let owner = inode_processes.get(inode);
        let remote_class = if remote_address.is_empty() {
            String::new()
        } else {
            classify_ip(&remote_address).as_str().to_string()
        };
        rows.push(NetworkRow {
            protocol: protocol.to_string(),
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            pid: owner.map(|owner| owner.pid.clone()).unwrap_or_default(),
            process_name: owner.map(|owner| owner.name.clone()).unwrap_or_default(),
            remote_class,
        });
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ProcessSocketOwner {
    pid: String,
    name: String,
}

#[cfg(unix)]
fn socket_inode_processes() -> BTreeMap<String, ProcessSocketOwner> {
    let mut owners = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return owners;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name().to_string_lossy().to_string();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let proc_dir = entry.path();
        let name = fs::read_to_string(proc_dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let fd_dir = proc_dir.join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.display().to_string();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            {
                if seen.insert(inode.to_string()) {
                    owners.insert(
                        inode.to_string(),
                        ProcessSocketOwner {
                            pid: pid.clone(),
                            name: name.clone(),
                        },
                    );
                }
            }
        }
    }
    owners
}

#[cfg(unix)]
fn decode_proc_address(value: &str) -> (String, String) {
    let Some((address_hex, port_hex)) = value.split_once(':') else {
        return (String::new(), String::new());
    };
    let port = u16::from_str_radix(port_hex, 16)
        .map(|port| port.to_string())
        .unwrap_or_default();
    let address = match address_hex.len() {
        8 => decode_ipv4(address_hex).unwrap_or_default(),
        32 => decode_ipv6(address_hex).unwrap_or_default(),
        _ => String::new(),
    };
    (address, port)
}

#[cfg(unix)]
fn decode_ipv4(value: &str) -> Option<String> {
    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(Ipv4Addr::from(bytes).to_string())
}

#[cfg(unix)]
fn decode_ipv6(value: &str) -> Option<String> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(chunk, 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

#[cfg(unix)]
fn tcp_state(value: &str) -> String {
    match value {
        "01" => "ESTABLISHED".to_string(),
        "02" => "SYN_SENT".to_string(),
        "03" => "SYN_RECV".to_string(),
        "04" => "FIN_WAIT1".to_string(),
        "05" => "FIN_WAIT2".to_string(),
        "06" => "TIME_WAIT".to_string(),
        "07" => "CLOSE".to_string(),
        "08" => "CLOSE_WAIT".to_string(),
        "09" => "LAST_ACK".to_string(),
        "0A" => "LISTEN".to_string(),
        "0B" => "CLOSING".to_string(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_ip_ranges() {
        assert_eq!(classify_ip("127.0.0.1"), IpClass::Loopback);
        assert_eq!(classify_ip("10.1.2.3"), IpClass::Private);
        assert_eq!(classify_ip("172.16.0.1"), IpClass::Private);
        assert_eq!(classify_ip("192.168.1.1"), IpClass::Private);
        assert_eq!(classify_ip("169.254.1.1"), IpClass::LinkLocal);
        assert_eq!(classify_ip("8.8.8.8"), IpClass::Public);
        assert_eq!(classify_ip("not-an-ip"), IpClass::Invalid);
    }
}
