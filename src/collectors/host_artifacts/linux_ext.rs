//! Linux P2 补充采集：内核安全参数、空密码账户、rc 文件注入（alias/函数/PROMPT_COMMAND/trap）、
//! 文件 capabilities（getcap 白名单）、包完整性（dpkg -V / rpm -Va 白名单）、
//! ps 与 /proc 进程对比（隐藏进程检测）。

use std::fs;
use std::process::Command;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::passwd_entries;

const KERNEL_PARAMS_HEADER: &str = "param,value,source\n";
const ACCOUNT_SECURITY_HEADER: &str = "user,issue,source\n";
const RC_FILES_HEADER: &str = "user,file,line_no,kind,detail\n";
const FILE_CAPABILITIES_HEADER: &str = "path,capabilities\n";
const PACKAGE_INTEGRITY_HEADER: &str = "tool,line\n";
const HIDDEN_PROCESSES_HEADER: &str = "pid,exe,cmdline,note\n";
const INSTALLED_PACKAGES_HEADER: &str = "manager,package,version\n";

#[derive(Debug, Clone, Serialize)]
struct KernelParamRow {
    param: String,
    value: String,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
struct AccountSecurityRow {
    user: String,
    issue: String,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
struct RcFileRow {
    user: String,
    file: String,
    line_no: u64,
    kind: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct FileCapabilityRow {
    path: String,
    capabilities: String,
}

#[derive(Debug, Clone, Serialize)]
struct PackageIntegrityRow {
    tool: String,
    line: String,
}

#[derive(Debug, Clone, Serialize)]
struct HiddenProcessRow {
    pid: String,
    exe: String,
    cmdline: String,
    note: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_kernel_params(layout)?;
    collect_rc_files(layout)?;
    collect_file_capabilities(layout, errors)?;
    collect_package_integrity(layout, errors)?;
    collect_hidden_processes(layout, errors)?;
    collect_installed_packages(layout)?;
    Ok(())
}

fn collect_kernel_params(layout: &OutputLayout) -> Result<()> {
    let params: [(&str, &str); 11] = [
        ("kptr_restrict", "/proc/sys/kernel/kptr_restrict"),
        ("dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"),
        ("randomize_va_space", "/proc/sys/kernel/randomize_va_space"),
        ("modules_disabled", "/proc/sys/kernel/modules_disabled"),
        (
            "kexec_load_disabled",
            "/proc/sys/kernel/kexec_load_disabled",
        ),
        (
            "perf_event_paranoid",
            "/proc/sys/kernel/perf_event_paranoid",
        ),
        (
            "unprivileged_bpf_disabled",
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        ),
        ("ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"),
        ("lockdown", "/sys/kernel/security/lockdown"),
        // 管道式 core_pattern（|/path）是已知的无文件持久化位。
        ("core_pattern", "/proc/sys/kernel/core_pattern"),
        ("modprobe", "/proc/sys/kernel/modprobe"),
    ];
    let mut rows = Vec::new();
    for (param, path) in params {
        if let Ok(content) = fs::read_to_string(path) {
            rows.push(KernelParamRow {
                param: param.to_string(),
                value: content.trim().to_string(),
                source: path.to_string(),
            });
        }
    }
    write_rows(&layout.kernel_params, KERNEL_PARAMS_HEADER, &rows)
}

/// Collect account security indicators that are required for every host snapshot.
///
/// This stays separate from the heavier Linux host-artifact bundle so that the
/// default `scan` path still checks for hidden/service accounts, duplicate UID 0
/// entries and password anomalies without enabling shell history, SUID walks or
/// other triage-only collectors.
pub fn collect_account_security(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let mut rows = Vec::new();
    match fs::read_to_string("/etc/shadow") {
        Ok(content) => {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 2 {
                    continue;
                }
                let user = fields[0];
                // 空密码字段（无哈希直接可登录）与弱哈希前缀。
                if fields[1].is_empty() {
                    rows.push(AccountSecurityRow {
                        user: user.to_string(),
                        issue: "empty_password".to_string(),
                        source: "/etc/shadow".to_string(),
                    });
                } else if fields[1].starts_with("$1$") {
                    rows.push(AccountSecurityRow {
                        user: user.to_string(),
                        issue: "weak_hash_md5".to_string(),
                        source: "/etc/shadow".to_string(),
                    });
                }
            }
        }
        Err(error) => {
            errors.push(super::collection_error(
                "account_security",
                "/etc/shadow",
                "read_shadow",
                "Linux shadow file could not be read; password checks are incomplete",
                Some(error.to_string()),
            ));
        }
    }
    match fs::read_to_string("/etc/passwd") {
        Ok(content) => {
            let mut uid_users: std::collections::BTreeMap<&str, Vec<&str>> =
                std::collections::BTreeMap::new();
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 7 {
                    continue;
                }
                uid_users.entry(fields[2]).or_default().push(fields[0]);
                let shell = fields[6];
                if fields[2].parse::<u32>().unwrap_or(u32::MAX) == 0 && fields[0] != "root" {
                    rows.push(AccountSecurityRow {
                        user: fields[0].to_string(),
                        issue: "additional_uid0_account".to_string(),
                        source: "/etc/passwd".to_string(),
                    });
                }
                if (fields[0] != "root" && fields[0].starts_with('.'))
                    || (fields[0] != "root"
                        && fields[2].parse::<u32>().unwrap_or(1000) < 1000
                        && !matches!(
                            shell,
                            "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | "/usr/bin/false"
                        ))
                {
                    rows.push(AccountSecurityRow {
                        user: fields[0].to_string(),
                        issue: "service_or_hidden_account_with_login_shell".to_string(),
                        source: "/etc/passwd".to_string(),
                    });
                }
            }
            for (uid, users) in uid_users {
                if users.len() > 1 {
                    rows.push(AccountSecurityRow {
                        user: users.join(","),
                        issue: format!("duplicate_uid:{uid}"),
                        source: "/etc/passwd".to_string(),
                    });
                }
            }
        }
        Err(error) => {
            errors.push(super::collection_error(
                "account_security",
                "/etc/passwd",
                "read_passwd",
                "Linux passwd file could not be read; hidden-account checks are incomplete",
                Some(error.to_string()),
            ));
        }
    }
    write_rows(&layout.account_security, ACCOUNT_SECURITY_HEADER, &rows)
}

fn collect_rc_files(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    let mut files: Vec<(String, std::path::PathBuf)> = Vec::new();
    for (user, home, _shell) in passwd_entries() {
        for name in [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".bash_login",
        ] {
            let path = home.join(name);
            if path.is_file() {
                files.push((user.clone(), path));
            }
        }
    }
    for (user, path) in files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            let kind = if trimmed.starts_with("alias ") && suspicious_command(&lower) {
                "suspicious_alias"
            } else if (trimmed.contains("function ") || trimmed.contains("() {"))
                && suspicious_command(&lower)
            {
                "suspicious_function"
            } else if trimmed.starts_with("PROMPT_COMMAND=") && suspicious_command(&lower) {
                "prompt_command_hook"
            } else if trimmed.starts_with("trap ") {
                "trap_hook"
            } else if trimmed.starts_with("export ")
                && (lower.contains("ld preload") || lower.contains("ld_preload"))
            {
                "ld_preload_export"
            } else {
                ""
            };
            if !kind.is_empty() {
                rows.push(RcFileRow {
                    user: user.clone(),
                    file: path.display().to_string(),
                    line_no: (index + 1) as u64,
                    kind: kind.to_string(),
                    detail: truncate(trimmed, 300).to_string(),
                });
            }
        }
    }
    write_rows(&layout.rc_files, RC_FILES_HEADER, &rows)
}

fn suspicious_command(lower: &str) -> bool {
    lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("base64")
        || lower.contains("nc -e")
        || lower.contains("/dev/tcp/")
        || lower.contains("python -c")
        || lower.contains("perl -e")
        || lower.contains("/tmp/")
        || lower.contains("/dev/shm")
}

fn collect_file_capabilities(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let mut rows = Vec::new();
    if let Some(getcap) = super::which("getcap") {
        match Command::new(getcap)
            .args([
                "-r", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc", "/tmp",
                "/var/tmp", "/home",
            ])
            .output()
        {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if let Some(row) = parse_getcap_line(line) {
                        rows.push(row);
                    }
                }
            }
            Ok(output) => errors.push(super::collection_error(
                "file_capabilities",
                "getcap",
                "getcap",
                "getcap exited non-zero",
                Some(format!("status={}", output.status)),
            )),
            Err(error) => errors.push(super::collection_error(
                "file_capabilities",
                "getcap",
                "getcap",
                "getcap could not be executed",
                Some(error.to_string()),
            )),
        }
    }
    write_rows(&layout.file_capabilities, FILE_CAPABILITIES_HEADER, &rows)
}

/// getcap 标准输出形态为 `path = cap_net_bind_service=ep`（" =" 分隔）；
/// 旧版 libcap 无 " =" 时退化为最后一个空格分隔。先按 " = " 切分可避免
/// 把 " =" 尾巴留在路径里。
fn parse_getcap_line(line: &str) -> Option<FileCapabilityRow> {
    let (path, caps) = line
        .rsplit_once(" = ")
        .or_else(|| line.rsplit_once(' '))?;
    let path = path.trim();
    let caps = caps.trim();
    if path.is_empty() || caps.is_empty() {
        return None;
    }
    Some(FileCapabilityRow {
        path: path.to_string(),
        capabilities: caps.to_string(),
    })
}

fn collect_package_integrity(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let mut rows = Vec::new();
    for (tool, args) in [("dpkg", vec!["-V"]), ("rpm", vec!["-Va"])] {
        if super::which(tool).is_none() {
            continue;
        }
        let Some(tool_path) = super::which(tool) else {
            continue;
        };
        match Command::new(tool_path).args(&args).output() {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if !line.trim().is_empty() {
                        rows.push(PackageIntegrityRow {
                            tool: tool.to_string(),
                            line: line.trim().to_string(),
                        });
                    }
                }
            }
            Ok(output) => errors.push(super::collection_error(
                "package_integrity",
                tool,
                "verify",
                "package verification exited non-zero",
                Some(format!("status={}", output.status)),
            )),
            Err(error) => errors.push(super::collection_error(
                "package_integrity",
                tool,
                "verify",
                "package verification could not be executed",
                Some(error.to_string()),
            )),
        }
        if !rows.is_empty() {
            break;
        }
    }
    write_rows(&layout.package_integrity, PACKAGE_INTEGRITY_HEADER, &rows)
}

fn collect_hidden_processes(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let mut rows = Vec::new();
    let Some(ps_path) = super::which("ps") else {
        errors.push(super::collection_error(
            "hidden_processes",
            "ps",
            "discover",
            "ps executable not found or is writable by group/other",
            None,
        ));
        return write_rows(&layout.hidden_processes, HIDDEN_PROCESSES_HEADER, &rows);
    };
    let ps_pids = match Command::new(ps_path).arg("-eo").arg("pid=").output() {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect::<std::collections::BTreeSet<u32>>(),
        _ => {
            errors.push(super::collection_error(
                "hidden_processes",
                "ps",
                "ps",
                "ps enumeration failed; hidden process comparison skipped",
                None,
            ));
            return write_rows(&layout.hidden_processes, HIDDEN_PROCESSES_HEADER, &rows);
        }
    };
    // /proc 直读枚举（绕过可能被劫持的 ps/libproc）。
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if ps_pids.contains(&pid) {
                continue;
            }
            let exe = fs::read_link(entry.path().join("exe"))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| format!("/proc/{}", pid));
            let cmdline = fs::read_to_string(entry.path().join("cmdline"))
                .map(|c| c.replace('\0', " ").trim().to_string())
                .unwrap_or_default();
            rows.push(HiddenProcessRow {
                pid: pid.to_string(),
                exe,
                cmdline,
                note: "present in /proc but missing from ps output".to_string(),
            });
        }
    }
    write_rows(&layout.hidden_processes, HIDDEN_PROCESSES_HEADER, &rows)
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

fn write_rows<T: serde::Serialize>(path: &std::path::Path, header: &str, rows: &[T]) -> Result<()> {
    if rows.is_empty() {
        writers::write_text(path, header)
    } else {
        writers::write_csv_serialize(path, rows)
    }
}

/// 已安装软件包清单（dpkg/rpm）：供与包完整性校验、二进制目录变更交叉比对。
fn collect_installed_packages(layout: &OutputLayout) -> Result<()> {
    let mut rows: Vec<PackageRow> = Vec::new();
    if let Some(dpkg_query) = super::which("dpkg-query") {
        let output = std::process::Command::new(dpkg_query)
            .args(["-W", "-f=${Package}\t${Version}\n"])
            .output();
        if let Ok(output) = output {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let mut parts = line.split('\t');
                if let (Some(package), Some(version)) = (parts.next(), parts.next()) {
                    rows.push(PackageRow {
                        manager: "dpkg".to_string(),
                        package: package.to_string(),
                        version: version.to_string(),
                    });
                }
            }
        }
    }
    if rows.is_empty() {
        let Some(rpm) = super::which("rpm") else {
            return write_rows(&layout.installed_packages, INSTALLED_PACKAGES_HEADER, &rows);
        };
        let output = std::process::Command::new(rpm)
            .args(["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
            .output();
        if let Ok(output) = output {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let mut parts = line.split('\t');
                if let (Some(package), Some(version)) = (parts.next(), parts.next()) {
                    rows.push(PackageRow {
                        manager: "rpm".to_string(),
                        package: package.to_string(),
                        version: version.to_string(),
                    });
                }
            }
        }
    }
    write_rows(&layout.installed_packages, INSTALLED_PACKAGES_HEADER, &rows)
}

#[derive(Debug, Clone, serde::Serialize)]
struct PackageRow {
    manager: String,
    package: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getcap_line_splits_on_equals_separator_without_tail() {
        let row =
            parse_getcap_line("/usr/bin/自定义工具 = cap_net_bind_service=ep").unwrap();
        assert_eq!(row.path, "/usr/bin/自定义工具");
        assert_eq!(row.capabilities, "cap_net_bind_service=ep");
    }

    #[test]
    fn getcap_line_falls_back_to_last_space() {
        let row = parse_getcap_line("/usr/bin/ping cap_net_raw=ep").unwrap();
        assert_eq!(row.path, "/usr/bin/ping");
        assert_eq!(row.capabilities, "cap_net_raw=ep");
    }

    #[test]
    fn getcap_line_rejects_malformed_lines() {
        assert!(parse_getcap_line("noseparator").is_none());
        assert!(parse_getcap_line("  ").is_none());
        assert!(parse_getcap_line("").is_none());
        assert!(parse_getcap_line("/path = ").is_none());
    }
}
