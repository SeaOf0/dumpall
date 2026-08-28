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

const SCHEDULED_TASKS_HEADER: &str = "name,path,state,command,user,source\n";
const STARTUP_ITEMS_HEADER: &str = "name,command,location,user,source\n";
const SERVICES_HEADER: &str = "name,display_name,state,start_mode,path,user,source\n";

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
        "persistence_scheduled_tasks",
        &layout.scheduled_tasks,
        SCHEDULED_TASKS_HEADER,
        &scheduled_task_commands(),
        errors,
        redact,
    )?;
    collect_text_command(
        "persistence_startup_items",
        &layout.startup_items,
        STARTUP_ITEMS_HEADER,
        &startup_item_commands(),
        errors,
        redact,
    )?;
    collect_text_command(
        "persistence_services",
        &layout.services,
        SERVICES_HEADER,
        &service_commands(),
        errors,
        redact,
    )
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct ScheduledTaskRow {
    name: String,
    path: String,
    state: String,
    command: String,
    user: String,
    source: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct StartupItemRow {
    name: String,
    command: String,
    location: String,
    user: String,
    source: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize)]
struct ServiceRow {
    name: String,
    display_name: String,
    state: String,
    start_mode: String,
    path: String,
    user: String,
    source: String,
}

#[cfg(unix)]
fn collect_unix(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    let mut scheduled = Vec::new();
    collect_crontab(
        Path::new("/etc/crontab"),
        "system_crontab",
        errors,
        redact,
        &mut scheduled,
    );
    collect_anacrontab(Path::new("/etc/anacrontab"), errors, redact, &mut scheduled);
    collect_cron_dir(
        Path::new("/etc/cron.d"),
        "cron_d",
        errors,
        redact,
        &mut scheduled,
    );
    for (dir, source) in [
        ("/var/spool/cron", "user_cron_spool"),
        ("/var/spool/cron/crontabs", "user_crontabs"),
    ] {
        collect_cron_dir(Path::new(dir), source, errors, redact, &mut scheduled);
    }

    let mut startup = Vec::new();
    collect_startup_dir(
        Path::new("/etc/init.d"),
        "sysv_init",
        errors,
        redact,
        &mut startup,
    );
    collect_startup_dir(
        Path::new("/etc/profile.d"),
        "shell_profile_d",
        errors,
        redact,
        &mut startup,
    );
    for path in [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/rc.local",
        "/etc/rc.d/rc.local",
    ] {
        collect_file_if_exists(
            Path::new(path),
            "system_shell_startup",
            errors,
            redact,
            &mut startup,
        );
    }

    let mut services = Vec::new();
    for dir in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ] {
        collect_systemd_units(
            Path::new(dir),
            errors,
            redact,
            &mut services,
            &mut scheduled,
        );
    }

    write_rows_or_header(&layout.scheduled_tasks, SCHEDULED_TASKS_HEADER, &scheduled)?;
    write_rows_or_header(&layout.startup_items, STARTUP_ITEMS_HEADER, &startup)?;
    write_rows_or_header(&layout.services, SERVICES_HEADER, &services)
}

#[cfg(windows)]
fn scheduled_task_commands() -> Vec<CommandSpec> {
    let script = r#"
Get-ScheduledTask |
  Select-Object @{Name='name';Expression={$_.TaskName}},
    @{Name='path';Expression={$_.TaskPath}},
    @{Name='state';Expression={$_.State}},
    @{Name='command';Expression={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}},
    @{Name='user';Expression={$_.Principal.UserId}},
    @{Name='source';Expression={'Get-ScheduledTask'}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(windows)]
fn startup_item_commands() -> Vec<CommandSpec> {
    let script = r#"
Get-CimInstance Win32_StartupCommand |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='command';Expression={$_.Command}},
    @{Name='location';Expression={$_.Location}},
    @{Name='user';Expression={$_.User}},
    @{Name='source';Expression={'Win32_StartupCommand'}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(windows)]
fn service_commands() -> Vec<CommandSpec> {
    let script = r#"
Get-CimInstance Win32_Service |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='display_name';Expression={$_.DisplayName}},
    @{Name='state';Expression={$_.State}},
    @{Name='start_mode';Expression={$_.StartMode}},
    @{Name='path';Expression={$_.PathName}},
    @{Name='user';Expression={$_.StartName}},
    @{Name='source';Expression={'Win32_Service'}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    vec![CommandSpec::powershell(script)]
}

#[cfg(unix)]
fn collect_crontab(
    path: &Path,
    source: &str,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    rows: &mut Vec<ScheduledTaskRow>,
) {
    let Some(content) = read_optional(path, "persistence_scheduled_tasks", errors) else {
        return;
    };
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || is_env_assignment(trimmed) {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let (user, command) = if source == "system_crontab" || source == "cron_d" {
            (
                fields.get(5).copied().unwrap_or_default(),
                fields[6..].join(" "),
            )
        } else {
            (
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
                fields[5..].join(" "),
            )
        };
        if command.trim().is_empty() {
            continue;
        }
        rows.push(ScheduledTaskRow {
            name: format!(
                "{}:{}",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("crontab"),
                index + 1
            ),
            path: path.display().to_string(),
            state: "configured".to_string(),
            command: maybe_redact(&command, redact),
            user: user.to_string(),
            source: source.to_string(),
        });
    }
}

#[cfg(unix)]
fn collect_cron_dir(
    path: &Path,
    source: &str,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    rows: &mut Vec<ScheduledTaskRow>,
) {
    if !path.exists() {
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(collection_error(
                "persistence_scheduled_tasks",
                path.display().to_string(),
                "read_dir",
                "cron directory could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_file() {
            collect_crontab(&child, source, errors, redact, rows);
        }
    }
}

#[cfg(unix)]
fn collect_anacrontab(
    path: &Path,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    rows: &mut Vec<ScheduledTaskRow>,
) {
    let Some(content) = read_optional(path, "persistence_scheduled_tasks", errors) else {
        return;
    };
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || is_env_assignment(trimmed) {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let command = fields[2..].join(" ");
        rows.push(ScheduledTaskRow {
            name: format!("anacrontab:{}", index + 1),
            path: path.display().to_string(),
            state: "configured".to_string(),
            command: maybe_redact(&command, redact),
            user: "root".to_string(),
            source: "anacron".to_string(),
        });
    }
}

#[cfg(unix)]
fn collect_startup_dir(
    path: &Path,
    source: &str,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    rows: &mut Vec<StartupItemRow>,
) {
    if !path.exists() {
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(collection_error(
                "persistence_startup_items",
                path.display().to_string(),
                "read_dir",
                "startup directory could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_file() {
            collect_file_if_exists(&child, source, errors, redact, rows);
        }
    }
}

#[cfg(unix)]
fn collect_file_if_exists(
    path: &Path,
    source: &str,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    rows: &mut Vec<StartupItemRow>,
) {
    let Some(content) = read_optional(path, "persistence_startup_items", errors) else {
        return;
    };
    let command = first_meaningful_line(&content).unwrap_or_default();
    rows.push(StartupItemRow {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string(),
        command: maybe_redact(&command, redact),
        location: path.display().to_string(),
        user: "root_or_system".to_string(),
        source: source.to_string(),
    });
}

#[cfg(unix)]
fn collect_systemd_units(
    path: &Path,
    errors: &mut Vec<CollectionError>,
    redact: bool,
    services: &mut Vec<ServiceRow>,
    scheduled: &mut Vec<ScheduledTaskRow>,
) {
    if !path.exists() {
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(collection_error(
                "persistence_services",
                path.display().to_string(),
                "read_dir",
                "systemd unit directory could not be read",
                Some(error.to_string()),
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let unit_path = entry.path();
        if !unit_path.is_file() {
            continue;
        }
        let Some(name) = unit_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !(name.ends_with(".service") || name.ends_with(".timer")) {
            continue;
        }
        let Some(content) = read_optional(&unit_path, "persistence_services", errors) else {
            continue;
        };
        let command = systemd_exec_summary(&content);
        let user = systemd_key(&content, "User").unwrap_or_else(|| "root_or_system".to_string());
        if name.ends_with(".timer") {
            scheduled.push(ScheduledTaskRow {
                name: name.to_string(),
                path: unit_path.display().to_string(),
                state: "configured".to_string(),
                command: maybe_redact(&command, redact),
                user,
                source: "systemd_timer".to_string(),
            });
        } else {
            services.push(ServiceRow {
                name: name.to_string(),
                display_name: systemd_key(&content, "Description").unwrap_or_default(),
                state: "configured".to_string(),
                start_mode: install_wanted_by(&content),
                path: maybe_redact(&command, redact),
                user,
                source: unit_path.display().to_string(),
            });
        }
    }
}

#[cfg(unix)]
fn read_optional(path: &Path, source: &str, errors: &mut Vec<CollectionError>) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            errors.push(collection_error(
                source,
                path.display().to_string(),
                "read_file",
                "persistence file could not be read",
                Some(error.to_string()),
            ));
            None
        }
    }
}

#[cfg(unix)]
fn is_env_assignment(line: &str) -> bool {
    line.contains('=') && !line.contains(char::is_whitespace)
}

#[cfg(unix)]
fn first_meaningful_line(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(unix)]
fn systemd_exec_summary(content: &str) -> String {
    let values = ["ExecStart", "ExecStartPre", "ExecStartPost"]
        .iter()
        .filter_map(|key| systemd_key(content, key))
        .collect::<Vec<_>>();
    if values.is_empty() {
        first_meaningful_line(content).unwrap_or_default()
    } else {
        values.join("; ")
    }
}

#[cfg(unix)]
fn systemd_key(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            return None;
        }
        let (name, value) = trimmed.split_once('=')?;
        if name.trim() == key {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

#[cfg(unix)]
fn install_wanted_by(content: &str) -> String {
    systemd_key(content, "WantedBy")
        .map(|value| format!("enabled_target:{value}"))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(unix)]
fn maybe_redact(value: &str, redact: bool) -> String {
    if redact {
        crate::safety::redact_text(value)
    } else {
        value.to_string()
    }
}

#[cfg(unix)]
fn write_rows_or_header<T: Serialize>(path: &Path, header: &str, rows: &[T]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, header)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}
