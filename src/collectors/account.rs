#[cfg(unix)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs;

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

const USERS_HEADER: &str = "name,enabled,uid_or_sid,description,last_logon,source\n";
const PRIVILEGED_USERS_HEADER: &str = "name,group,uid_or_sid,source\n";
const LOGONS_HEADER: &str = "user,terminal,source,logon_time,detail\n";

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
        "account_users",
        &layout.users,
        USERS_HEADER,
        &user_commands(),
        errors,
        redact,
    )?;
    collect_text_command(
        "account_privileged_users",
        &layout.privileged_users,
        PRIVILEGED_USERS_HEADER,
        &privileged_user_commands(),
        errors,
        redact,
    )?;
    collect_text_command(
        "account_logons",
        &layout.logons,
        LOGONS_HEADER,
        &logon_commands(),
        errors,
        redact,
    )
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct UserRow {
    name: String,
    enabled: String,
    uid_or_sid: String,
    description: String,
    last_logon: String,
    source: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct PrivilegedUserRow {
    name: String,
    group: String,
    uid_or_sid: String,
    source: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct LogonRow {
    user: String,
    terminal: String,
    source: String,
    logon_time: String,
    detail: String,
}

#[cfg(unix)]
fn collect_unix(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let passwd = read_passwd(errors);
    let groups = read_groups(errors);
    let shadow_locked = read_shadow_lock_status();

    let mut users = Vec::new();
    for user in passwd.values() {
        let enabled = shadow_locked
            .get(&user.name)
            .map(|locked| (!locked).to_string())
            .unwrap_or_else(|| "unknown".to_string());
        users.push(UserRow {
            name: user.name.clone(),
            enabled,
            uid_or_sid: user.uid.clone(),
            description: user.gecos.clone(),
            last_logon: String::new(),
            source: "/etc/passwd".to_string(),
        });
    }

    let mut privileged = Vec::new();
    for user in passwd.values().filter(|user| user.uid == "0") {
        privileged.push(PrivilegedUserRow {
            name: user.name.clone(),
            group: "uid0".to_string(),
            uid_or_sid: user.uid.clone(),
            source: "/etc/passwd".to_string(),
        });
    }
    for group in groups.values().filter(|group| {
        matches!(
            group.name.as_str(),
            "sudo" | "wheel" | "admin" | "root" | "docker"
        )
    }) {
        for member in &group.members {
            let uid = passwd
                .get(member)
                .map(|user| user.uid.clone())
                .unwrap_or_default();
            privileged.push(PrivilegedUserRow {
                name: member.clone(),
                group: group.name.clone(),
                uid_or_sid: uid,
                source: "/etc/group".to_string(),
            });
        }
    }
    privileged.sort_by(|left, right| (&left.group, &left.name).cmp(&(&right.group, &right.name)));
    privileged.dedup_by(|left, right| left.name == right.name && left.group == right.group);

    let logons = current_logons(errors);

    write_rows_or_header(&layout.users, USERS_HEADER, &users)?;
    write_rows_or_header(
        &layout.privileged_users,
        PRIVILEGED_USERS_HEADER,
        &privileged,
    )?;
    write_rows_or_header(&layout.logons, LOGONS_HEADER, &logons)
}

#[cfg(windows)]
fn user_commands() -> Vec<CommandSpec> {
    let script = r#"
$rows = @()
try {
  $rows += Get-LocalUser -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Name}}, @{Name='enabled';Expression={$_.Enabled}}, @{Name='uid_or_sid';Expression={$_.SID}}, @{Name='description';Expression={$_.Description}}, @{Name='last_logon';Expression={$_.LastLogon}}, @{Name='source';Expression={'Get-LocalUser'}}
} catch {}
try {
  $rows += Get-CimInstance Win32_UserAccount -Filter "LocalAccount=False" -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Caption}}, @{Name='enabled';Expression={-not $_.Disabled}}, @{Name='uid_or_sid';Expression={$_.SID}}, @{Name='description';Expression={$_.Description}}, @{Name='last_logon';Expression={''}}, @{Name='source';Expression={'Win32_UserAccount(domain)'}}
} catch {}
if ($rows.Count -eq 0) {
  $rows += [pscustomobject]@{ name=''; enabled=''; uid_or_sid=''; description=''; last_logon=''; source='user_enumeration_failed_or_empty' }
}
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(windows)]
fn privileged_user_commands() -> Vec<CommandSpec> {
    let script = r#"
Get-LocalGroupMember -Group Administrators |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='group';Expression={'Administrators'}},
    @{Name='uid_or_sid';Expression={$_.SID}},
    @{Name='source';Expression={'Get-LocalGroupMember'}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(windows)]
fn logon_commands() -> Vec<CommandSpec> {
    let script = r#"
$user = [Environment]::UserName
$domain = [Environment]::UserDomainName
[pscustomobject]@{
  user = "$domain\$user"
  terminal = ''
  source = 'current_session'
  logon_time = ''
  detail = 'Windows current session only; full EVTX parsing is out of scope.'
} | ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct PasswdUser {
    name: String,
    uid: String,
    gecos: String,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct GroupRow {
    name: String,
    members: BTreeSet<String>,
}

/// 小型系统账号文件的 lossy 读取：/etc/passwd 的 GECOS 等字段可能含 GBK
/// 等非 UTF-8 内容，read_to_string 会整文件失败导致账号清单全部丢失；
/// lossy 保留行内容，仅替换不可解码字节。
#[cfg(unix)]
fn read_text_lossy(path: &str) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(unix)]
fn read_passwd(errors: &mut Vec<CollectionError>) -> BTreeMap<String, PasswdUser> {
    let mut users = BTreeMap::new();
    let content = match read_text_lossy("/etc/passwd") {
        Some(content) => content,
        None => {
            errors.push(collection_error(
                "account_users",
                "/etc/passwd",
                "read_passwd",
                "Linux account file could not be read",
                None,
            ));
            return users;
        }
    };
    for line in content.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 5 {
            users.insert(
                fields[0].to_string(),
                PasswdUser {
                    name: fields[0].to_string(),
                    uid: fields[2].to_string(),
                    gecos: fields[4].to_string(),
                },
            );
        }
    }
    users
}

#[cfg(unix)]
fn read_groups(errors: &mut Vec<CollectionError>) -> BTreeMap<String, GroupRow> {
    let mut groups = BTreeMap::new();
    let content = match read_text_lossy("/etc/group") {
        Some(content) => content,
        None => {
            errors.push(collection_error(
                "account_privileged_users",
                "/etc/group",
                "read_group",
                "Linux group file could not be read",
                None,
            ));
            return groups;
        }
    };
    for line in content.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 {
            groups.insert(
                fields[0].to_string(),
                GroupRow {
                    name: fields[0].to_string(),
                    members: fields[3]
                        .split(',')
                        .filter(|member| !member.trim().is_empty())
                        .map(|member| member.trim().to_string())
                        .collect(),
                },
            );
        }
    }
    groups
}

#[cfg(unix)]
fn read_shadow_lock_status() -> BTreeMap<String, bool> {
    let mut values = BTreeMap::new();
    let Some(content) = read_text_lossy("/etc/shadow") else {
        return values;
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 2 {
            let marker = fields[1];
            values.insert(
                fields[0].to_string(),
                marker.starts_with('!') || marker.starts_with('*'),
            );
        }
    }
    values
}

#[cfg(unix)]
fn current_logons(errors: &mut Vec<CollectionError>) -> Vec<LogonRow> {
    let mut rows = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/self/mounts") else {
        errors.push(collection_error(
            "account_logons",
            "/proc/self/mounts",
            "read_mounts",
            "Linux current session context could not be read",
            None,
        ));
        return rows;
    };
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let tty = std::env::var("SSH_TTY").unwrap_or_default();
    let has_wsl_mount = content.lines().any(|line| line.contains("drvfs"));
    rows.push(LogonRow {
        user,
        terminal: tty,
        source: "current_session".to_string(),
        logon_time: String::new(),
        detail: if has_wsl_mount {
            "Linux current session; WSL drvfs mount observed".to_string()
        } else {
            "Linux current session".to_string()
        },
    });
    rows
}

#[cfg(unix)]
fn write_rows_or_header<T: Serialize>(
    path: &std::path::Path,
    header: &str,
    rows: &[T],
) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, header)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}
