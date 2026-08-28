//! SSH 侧痕迹采集：每用户 authorized_keys / known_hosts / ssh config，
//! 以及 /etc/ssh/sshd_config 的可疑配置项。

use std::fs;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::passwd_entries;

const KEYS_HEADER: &str = "user,home_dir,file,kind,line_no,detail,mtime\n";
const SSHD_HEADER: &str = "key,value,flag,source_file,line_no\n";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// known_hosts 每文件最多登记的主机条目数，防止超大文件撑爆输出。
const MAX_KNOWN_HOSTS_ROWS: usize = 200;

#[derive(Debug, Clone, Serialize)]
struct SshKeyRow {
    user: String,
    home_dir: String,
    file: String,
    kind: String,
    line_no: u64,
    detail: String,
    mtime: String,
}

#[derive(Debug, Clone, Serialize)]
struct SshdFlagRow {
    key: String,
    value: String,
    flag: String,
    source_file: String,
    line_no: u64,
}

pub fn collect(layout: &OutputLayout, _errors: &mut Vec<CollectionError>) -> Result<()> {
    let mut key_rows = Vec::new();
    for (user, home, _shell) in passwd_entries() {
        collect_user_ssh(&user, &home, &mut key_rows);
    }
    write_keys(layout, &key_rows)?;

    let mut flag_rows = Vec::new();
    collect_sshd_config(&mut flag_rows);
    collect_ssh_client_config(&mut flag_rows);
    if flag_rows.is_empty() {
        writers::write_text(&layout.sshd_config_flags, SSHD_HEADER)
    } else {
        writers::write_csv_serialize(&layout.sshd_config_flags, &flag_rows)
    }
}

fn write_keys(layout: &OutputLayout, rows: &[SshKeyRow]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(&layout.ssh_keys, KEYS_HEADER)
    } else {
        writers::write_csv_serialize(&layout.ssh_keys, rows)
    }
}

fn collect_user_ssh(user: &str, home: &std::path::Path, rows: &mut Vec<SshKeyRow>) {
    let ssh_dir = home.join(".ssh");
    let Ok(entries) = fs::read_dir(&ssh_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let mtime = metadata
            .modified()
            .ok()
            .map(crate::time_utils::system_time_to_iso)
            .unwrap_or_default();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let kind = if name == "authorized_keys" || name.starts_with("authorized_keys") {
            "authorized_keys"
        } else if name == "known_hosts" {
            "known_hosts"
        } else if name == "config" {
            "ssh_config"
        } else if name == "rc" {
            "ssh_rc"
        } else if name == "environment" {
            "ssh_environment"
        } else {
            continue;
        };
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        // GBK 等非 UTF-8 内容 lossy 保留，避免静默丢证据。
        let content = String::from_utf8_lossy(&bytes);
        // known_hosts 条目按"每文件"计数封顶（与注释一致）。
        let mut known_hosts_rows = 0usize;
        for (index, line) in content.lines().enumerate() {
            let line_no = (index + 1) as u64;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let detail = match kind {
                "authorized_keys" => {
                    let mut parts = trimmed.split_whitespace();
                    let first = parts.next().unwrap_or("");
                    if first.contains('=')
                        || first.starts_with("ssh-")
                        || first.starts_with("ecdsa-")
                        || first.starts_with("sk-")
                    {
                        // 可能带 options 前缀：取注释尾部
                        let comment = trimmed.split_whitespace().last().unwrap_or("");
                        format!("{} ... {}", first, comment)
                    } else {
                        format!("options_prefix: {}", truncate(first, 120))
                    }
                }
                "known_hosts" => {
                    if known_hosts_rows >= MAX_KNOWN_HOSTS_ROWS {
                        continue;
                    }
                    known_hosts_rows += 1;
                    truncate(trimmed.split_whitespace().next().unwrap_or(""), 200).to_string()
                }
                "ssh_environment" => "environment_entry".to_string(),
                _ => truncate(trimmed, 160).to_string(),
            };
            rows.push(SshKeyRow {
                user: user.to_string(),
                home_dir: home.display().to_string(),
                file: path.display().to_string(),
                kind: kind.to_string(),
                line_no,
                detail,
                mtime: mtime.clone(),
            });
        }
    }
}

fn collect_ssh_client_config(rows: &mut Vec<SshdFlagRow>) {
    let path = "/etc/ssh/ssh_config";
    let Some(content) = read_lossy(std::path::Path::new(path)) else {
        return;
    };
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key_raw, value_raw)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let key = key_raw.to_ascii_lowercase();
        if !matches!(
            key.as_str(),
            "proxycommand" | "proxyjump" | "localcommand" | "permitlocalcommand" | "include"
        ) {
            continue;
        }
        rows.push(SshdFlagRow {
            key,
            value: value_raw.trim().to_string(),
            flag: "ssh_client_execution_or_include".to_string(),
            source_file: path.to_string(),
            line_no: (index + 1) as u64,
        });
    }
}

fn collect_sshd_config(rows: &mut Vec<SshdFlagRow>) {
    let Some(content) = read_lossy(std::path::Path::new("/etc/ssh/sshd_config")) else {
        return;
    };
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key_raw, value_raw)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let key = key_raw.to_ascii_lowercase();
        let value = value_raw.trim().to_string();
        let flag = flag_for_sshd_key(&key, &value);
        if !flag.is_empty() {
            rows.push(SshdFlagRow {
                key,
                value,
                flag: flag.to_string(),
                source_file: "/etc/ssh/sshd_config".to_string(),
                line_no: (index + 1) as u64,
            });
        }
    }
    // sshd_config.d 片段同样检查。
    if let Ok(entries) = fs::read_dir("/etc/ssh/sshd_config.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.to_string_lossy().ends_with(".conf") {
                continue;
            }
            let Some(content) = read_lossy(&path) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let Some((key_raw, value_raw)) = trimmed.split_once(char::is_whitespace) else {
                    continue;
                };
                let key = key_raw.to_ascii_lowercase();
                let value = value_raw.trim().to_string();
                let flag = flag_for_sshd_key(&key, &value);
                if !flag.is_empty() {
                    rows.push(SshdFlagRow {
                        key,
                        value,
                        flag: flag.to_string(),
                        source_file: path.display().to_string(),
                        line_no: (index + 1) as u64,
                    });
                }
            }
        }
    }
}

fn flag_for_sshd_key(key: &str, value: &str) -> &'static str {
    match key {
        "permitrootlogin" if value.eq_ignore_ascii_case("yes") => "root_login_allowed",
        "passwordauthentication" if value.eq_ignore_ascii_case("yes") => "password_auth_allowed",
        "permitemptypasswords" if value.eq_ignore_ascii_case("yes") => "empty_password_allowed",
        "authorizedkeysfile" if !value.contains(".ssh/authorized_keys") => {
            "non_default_authorized_keys_file"
        }
        "authorizedkeyscommand" => "authorized_keys_command_configured",
        "forcecommand" => "force_command_configured",
        "authorizedprincipalsfile" => "authorized_principals_configured",
        "trustedusercakeys" | "trustedusercacafile" => "trusted_user_ca_configured",
        _ => "",
    }
}

fn truncate(value: &str, max: usize) -> &str {
    value.get(..max).unwrap_or_else(|| {
        let mut end = max.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    })
}

/// 读取配置/密钥文件并 lossy 解码：GBK 等非 UTF-8 内容保留证据（U+FFFD 替换无效字节）。
fn read_lossy(path: &std::path::Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_flags_match_risky_settings() {
        // 调用方统一传入小写键。
        assert_eq!(
            flag_for_sshd_key("permitrootlogin", "yes"),
            "root_login_allowed"
        );
        assert_eq!(flag_for_sshd_key("permitrootlogin", "no"), "");
        assert_eq!(
            flag_for_sshd_key("authorizedkeysfile", "/tmp/keys/%u"),
            "non_default_authorized_keys_file"
        );
        assert_eq!(
            flag_for_sshd_key("forcecommand", "/opt/x.sh"),
            "force_command_configured"
        );
    }
}
