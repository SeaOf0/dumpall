#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;

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

const PROCESS_HEADER: &str =
    "pid,ppid,name,executable_path,command_line,started_at,user,is_web_related\n";

pub fn collect(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        collect_unix(layout, errors, redact)
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
        "process",
        &layout.processes,
        PROCESS_HEADER,
        &process_commands(),
        errors,
        redact,
    )?;
    collect_text_command(
        "process_tree",
        &layout.process_tree,
        "",
        &process_tree_commands(),
        errors,
        redact,
    )
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct ProcessRow {
    pid: String,
    ppid: String,
    name: String,
    executable_path: String,
    command_line: String,
    started_at: String,
    user: String,
    is_web_related: bool,
}

#[cfg(unix)]
fn linux_process_rows(errors: &mut Vec<CollectionError>, redact: bool) -> Vec<ProcessRow> {
    let uid_names = linux_uid_names();
    let mut rows = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(collection_error(
                "process",
                "/proc",
                "read_dir",
                "process directory could not be read",
                Some(error.to_string()),
            ));
            return rows;
        }
    };

    for entry in entries.flatten() {
        let pid = entry.file_name().to_string_lossy().to_string();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let proc_dir = entry.path();
        let status = read_to_string_optional(&proc_dir.join("status"));
        let stat = read_to_string_optional(&proc_dir.join("stat"));
        let name = status
            .as_deref()
            .and_then(status_value("Name"))
            .or_else(|| stat.as_deref().and_then(stat_name))
            .unwrap_or_else(|| "unknown".to_string());
        let ppid = status
            .as_deref()
            .and_then(status_value("PPid"))
            .or_else(|| stat.as_deref().and_then(stat_ppid))
            .unwrap_or_default();
        let uid = status.as_deref().and_then(status_value("Uid"));
        let user = uid
            .as_deref()
            .and_then(|uid| uid_names.get(uid).cloned())
            .or(uid)
            .unwrap_or_default();
        let executable_path = fs::read_link(proc_dir.join("exe"))
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let mut command_line = read_cmdline(&proc_dir.join("cmdline"))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| name.clone());
        if redact {
            command_line = crate::safety::redact_text(&command_line);
        }
        let started_at = stat
            .as_deref()
            .and_then(stat_start_ticks)
            .map(|ticks| format!("boot_ticks:{ticks}"))
            .unwrap_or_default();
        let is_web_related = is_web_related(&name, &command_line);
        rows.push(ProcessRow {
            pid,
            ppid,
            name,
            executable_path,
            command_line,
            started_at,
            user,
            is_web_related,
        });
    }

    rows.sort_by_key(|row| row.pid.parse::<u64>().unwrap_or(u64::MAX));
    rows
}

#[cfg(unix)]
fn collect_unix(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    let rows = linux_process_rows(errors, redact);
    if rows.is_empty() {
        writers::write_text(&layout.processes, PROCESS_HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.processes, &rows)?;
    }
    write_process_tree(&layout.process_tree, &rows)
}

#[cfg(unix)]
fn write_process_tree(path: &Path, rows: &[ProcessRow]) -> Result<()> {
    let mut content = String::new();
    for row in rows {
        content.push_str(&format!(
            "{} <- {} {} {}\n",
            row.pid, row.ppid, row.name, row.command_line
        ));
    }
    writers::write_text(path, &content)
}

#[cfg(windows)]
fn process_commands() -> Vec<CommandSpec> {
    let script = r#"
$webNames = @('nginx','httpd','apache','apache2','php-fpm','java','tomcat','w3wp','dotnet','node','gunicorn','uwsgi','daphne','weblogic','jboss','wildfly','caddy')
Get-CimInstance Win32_Process |
  ForEach-Object {
    $owner = ''
    try {
      $info = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
      if ($info.ReturnValue -eq 0 -and $info.User) {
        $owner = if ($info.Domain) { "$($info.Domain)\$($info.User)" } else { [string]$info.User }
      }
    } catch {}
    $n = [string]$_.Name
    $c = [string]$_.CommandLine
    $isWeb = (($webNames | Where-Object { $n -match $_ -or $c -match $_ } | Select-Object -First 1) -ne $null)
    [PSCustomObject]@{
      pid = $_.ProcessId
      ppid = $_.ParentProcessId
      name = $_.Name
      executable_path = $_.ExecutablePath
      command_line = $_.CommandLine
      started_at = $_.CreationDate
      user = $owner
      is_web_related = $isWeb
    }
  } |
  Select-Object @{Name='pid';Expression={$_.pid}},
    @{Name='ppid';Expression={$_.ppid}},
    @{Name='name';Expression={$_.name}},
    @{Name='executable_path';Expression={$_.executable_path}},
    @{Name='command_line';Expression={$_.command_line}},
    @{Name='started_at';Expression={$_.started_at}},
    @{Name='user';Expression={$_.user}},
    @{Name='is_web_related';Expression={$_.is_web_related}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(windows)]
fn process_tree_commands() -> Vec<CommandSpec> {
    let script = r#"
Get-CimInstance Win32_Process |
  Sort-Object ParentProcessId,ProcessId |
  ForEach-Object { '{0} <- {1} {2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name }
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(unix)]
fn linux_uid_names() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(content) = fs::read_to_string("/etc/passwd") else {
        return map;
    };
    for line in content.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            map.insert(fields[2].to_string(), fields[0].to_string());
        }
    }
    map
}

#[cfg(unix)]
fn read_to_string_optional(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

#[cfg(unix)]
fn read_cmdline(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter_map(|part| {
                if part.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(part).to_string())
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(unix)]
fn status_value(key: &'static str) -> impl Fn(&str) -> Option<String> {
    move |status: &str| {
        status.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name == key {
                value.split_whitespace().next().map(str::to_string)
            } else {
                None
            }
        })
    }
}

#[cfg(unix)]
fn stat_name(stat: &str) -> Option<String> {
    let start = stat.find('(')?;
    let end = stat.rfind(')')?;
    Some(stat[start + 1..end].to_string())
}

#[cfg(unix)]
fn stat_ppid(stat: &str) -> Option<String> {
    stat_after_comm(stat)
        .and_then(|rest| rest.split_whitespace().nth(1))
        .map(str::to_string)
}

#[cfg(unix)]
fn stat_start_ticks(stat: &str) -> Option<String> {
    stat_after_comm(stat)
        .and_then(|rest| rest.split_whitespace().nth(19))
        .map(str::to_string)
}

#[cfg(unix)]
fn stat_after_comm(stat: &str) -> Option<&str> {
    let end = stat.rfind(')')?;
    stat.get(end + 2..)
}

#[cfg(unix)]
fn is_web_related(name: &str, command_line: &str) -> bool {
    let haystack = format!("{} {}", name, command_line).to_ascii_lowercase();
    [
        "nginx", "httpd", "apache", "apache2", "php-fpm", "java", "tomcat", "dotnet", "node",
        "gunicorn", "uwsgi", "daphne", "weblogic", "jboss", "wildfly", "caddy",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}
