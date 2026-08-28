//! Linux 持久化深挖：at 队列、rc*.d、用户级 systemd、XDG autostart、udev 规则、
//! ld.so.preload、PAM 异常模块、TCP Wrappers、Python .pth 后门、motd。

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::walk_dir_capped;

const HEADER: &str = "kind,path,detail,flag\n";
/// 单文件最大读取字节数。
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct PersistenceMiscRow {
    kind: String,
    path: String,
    detail: String,
    flag: String,
}

const PAM_MODULE_DIRS: &[&str] = &[
    "/lib/security",
    "/usr/lib/security",
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security",
    "/lib64/security",
    "/usr/lib64/security",
];

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let mut rows = Vec::new();
    collect_at_queue(&mut rows);
    collect_rc_dirs(&mut rows);
    collect_user_systemd(&mut rows, errors);
    collect_xdg_autostart(&mut rows, errors);
    collect_udev_rules(&mut rows);
    collect_ld_preload(&mut rows);
    collect_pam(&mut rows);
    collect_tcp_wrappers(&mut rows);
    collect_python_pth(&mut rows, errors);
    collect_motd(&mut rows);
    collect_systemd_timers(&mut rows, errors);
    collect_kernel_module_config(&mut rows);
    collect_audit_and_repositories(&mut rows, errors);
    collect_module_security(&mut rows);
    if rows.is_empty() {
        writers::write_text(&layout.persistence_misc, HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.persistence_misc, &rows)?;
    }
    Ok(())
}

fn collect_at_queue(rows: &mut Vec<PersistenceMiscRow>) {
    for dir in ["/var/spool/at", "/var/spool/cron/atjobs"] {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file = entry.path();
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    rows.push(PersistenceMiscRow {
                        kind: "at_job".to_string(),
                        path: file.display().to_string(),
                        detail: head_content(&file, 512),
                        flag: String::new(),
                    });
                }
            }
        }
    }
}

fn collect_rc_dirs(rows: &mut Vec<PersistenceMiscRow>) {
    for level in 0..=6 {
        let dir = format!("/etc/rc{level}.d");
        let path = std::path::Path::new(&dir);
        if !path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('S') || name.starts_with('K') {
                    let target = fs::read_link(&file)
                        .map(|t| t.to_string_lossy().to_string())
                        .unwrap_or_default();
                    rows.push(PersistenceMiscRow {
                        kind: "rc_script".to_string(),
                        path: file.display().to_string(),
                        detail: format!("link -> {target}"),
                        flag: String::new(),
                    });
                }
            }
        }
    }
}

fn collect_user_systemd(rows: &mut Vec<PersistenceMiscRow>, errors: &mut Vec<CollectionError>) {
    let mut homes: Vec<std::path::PathBuf> = Vec::new();
    for (_user, home, _shell) in super::passwd_entries() {
        homes.push(home);
    }
    for home in homes {
        let units_dir = home.join(".config").join("systemd").join("user");
        if !units_dir.exists() {
            continue;
        }
        collect_unit_files(&units_dir, "user_systemd", rows, errors);
    }
}

fn collect_unit_files(
    dir: &Path,
    kind: &str,
    rows: &mut Vec<PersistenceMiscRow>,
    errors: &mut Vec<CollectionError>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".service") || name.ends_with(".timer") {
            let content = read_evidence_capped(&path, kind, errors);
            let exec_start = content
                .lines()
                .find(|line| line.trim_start().starts_with("ExecStart"))
                .map(|line| line.trim().to_string())
                .unwrap_or_default();
            rows.push(PersistenceMiscRow {
                kind: kind.to_string(),
                path: path.display().to_string(),
                detail: exec_start,
                flag: String::new(),
            });
        }
    }
}

/// systemd 定时器独立清点：.timer 单元的调度字段与触发目标
/// （/etc/systemd/system、/run/systemd/system、/usr/lib/systemd/system）。
fn collect_systemd_timers(rows: &mut Vec<PersistenceMiscRow>, errors: &mut Vec<CollectionError>) {
    for base in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
    ] {
        let dir = std::path::Path::new(base);
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".timer") {
                continue;
            }
            let content = read_evidence_capped(&path, "systemd_timer", errors);
            let mut schedule = String::new();
            let mut target = String::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("OnCalendar")
                    || trimmed.starts_with("OnBootSec")
                    || trimmed.starts_with("OnUnitActiveSec")
                {
                    if !schedule.is_empty() {
                        schedule.push(';');
                    }
                    schedule.push_str(trimmed);
                } else if trimmed.starts_with("Unit=") {
                    target = trimmed.to_string();
                }
            }
            rows.push(PersistenceMiscRow {
                kind: "systemd_timer".to_string(),
                path: path.display().to_string(),
                detail: format!("{schedule} {target}").trim().to_string(),
                flag: String::new(),
            });
        }
    }
}

/// 内核模块持久化配置位：/etc/modules 与 /etc/modprobe.d/*.conf。
fn collect_kernel_module_config(rows: &mut Vec<PersistenceMiscRow>) {
    if let Some(content) = read_lossy(Path::new("/etc/modules")) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            rows.push(PersistenceMiscRow {
                kind: "kernel_module_load".to_string(),
                path: "/etc/modules".to_string(),
                detail: trimmed.to_string(),
                flag: String::new(),
            });
        }
    }
    if let Ok(entries) = fs::read_dir("/etc/modprobe.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".conf") {
                continue;
            }
            let Some(content) = read_lossy(&path) else {
                continue;
            };
            let install_lines: Vec<&str> = content
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    trimmed.starts_with("install ") || trimmed.starts_with("options ")
                })
                .collect();
            if install_lines.is_empty() {
                continue;
            }
            rows.push(PersistenceMiscRow {
                kind: "modprobe_config".to_string(),
                path: path.display().to_string(),
                detail: install_lines.join("; "),
                flag: String::new(),
            });
        }
    }
}

fn collect_audit_and_repositories(
    rows: &mut Vec<PersistenceMiscRow>,
    errors: &mut Vec<CollectionError>,
) {
    for file in ["/etc/audit/auditd.conf", "/etc/audit/rules.d"] {
        let path = std::path::Path::new(file);
        if path.is_file() {
            rows.push(PersistenceMiscRow {
                kind: "audit_config".to_string(),
                path: file.to_string(),
                detail: head_content(path, 1024),
                flag: String::new(),
            });
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let child = entry.path();
                    if child.is_file() {
                        rows.push(PersistenceMiscRow {
                            kind: "audit_rule_file".to_string(),
                            path: child.display().to_string(),
                            detail: head_content(&child, 1024),
                            flag: String::new(),
                        });
                    }
                }
            }
        }
    }
    for root in ["/etc/apt", "/etc/yum.repos.d", "/etc/dnf"] {
        let path = std::path::Path::new(root);
        if !path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(path, |child, is_dir| {
            if is_dir {
                return true;
            }
            let name = child
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            if name.ends_with(".list") || name.ends_with(".repo") || name.starts_with("trusted.gpg")
            {
                let detail = head_content(child, 512);
                let flag = if detail.contains("http://") || detail.contains("gpgcheck=0") {
                    "untrusted_source".to_string()
                } else {
                    String::new()
                };
                rows.push(PersistenceMiscRow {
                    kind: "package_repository".to_string(),
                    path: child.display().to_string(),
                    detail,
                    flag,
                });
            }
            true
        });
        if walk_stats.failed_dirs > 0 {
            errors.push(super::collection_error(
                "persistence_misc",
                root,
                "walk_dir_capped",
                format!(
                    "{} director(y/ies) under {root} could not be read (permission or removed mid-scan); those subtrees are not covered",
                    walk_stats.failed_dirs
                ),
                None,
            ));
        }
    }
}

fn collect_module_security(rows: &mut Vec<PersistenceMiscRow>) {
    for (name, path, flag) in [
        (
            "module_sig_enforce",
            "/proc/sys/kernel/module_sig_enforce",
            "module_signature_policy",
        ),
        (
            "kernel_tainted",
            "/proc/sys/kernel/tainted",
            "kernel_taint_state",
        ),
    ] {
        if let Ok(value) = fs::read_to_string(path) {
            rows.push(PersistenceMiscRow {
                kind: name.to_string(),
                path: path.to_string(),
                detail: value.trim().to_string(),
                flag: flag.to_string(),
            });
        }
    }
}

fn collect_xdg_autostart(rows: &mut Vec<PersistenceMiscRow>, errors: &mut Vec<CollectionError>) {
    let mut dirs: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from("/etc/xdg/autostart")];
    for (_user, home, _shell) in super::passwd_entries() {
        dirs.push(home.join(".config").join("autostart"));
    }
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.to_string_lossy().ends_with(".desktop") {
                continue;
            }
            let content = read_evidence_capped(&path, "xdg_autostart", errors);
            let exec = content
                .lines()
                .find_map(|line| {
                    line.trim_start()
                        .strip_prefix("Exec=")
                        .map(|v| v.to_string())
                })
                .unwrap_or_default();
            rows.push(PersistenceMiscRow {
                kind: "xdg_autostart".to_string(),
                path: path.display().to_string(),
                detail: exec,
                flag: String::new(),
            });
        }
    }
}

fn collect_udev_rules(rows: &mut Vec<PersistenceMiscRow>) {
    for dir in [
        "/etc/udev/rules.d",
        "/lib/udev/rules.d",
        "/usr/lib/udev/rules.d",
    ] {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file = entry.path();
                if !file.to_string_lossy().ends_with(".rules") {
                    continue;
                }
                let Some(content) = read_lossy(&file) else {
                    continue;
                };
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') || trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.contains("RUN+=")
                        || trimmed.contains("PROGRAM==")
                        || trimmed.contains("IMPORT{")
                    {
                        rows.push(PersistenceMiscRow {
                            kind: "udev_rule".to_string(),
                            path: file.display().to_string(),
                            detail: truncate(trimmed, 300).to_string(),
                            flag: String::new(),
                        });
                    }
                }
            }
        }
    }
}

fn collect_ld_preload(rows: &mut Vec<PersistenceMiscRow>) {
    if let Some(content) = read_lossy(Path::new("/etc/ld.so.preload")) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            rows.push(PersistenceMiscRow {
                kind: "ld_so_preload".to_string(),
                path: trimmed.to_string(),
                detail: "/etc/ld.so.preload entry".to_string(),
                flag: "high_signal".to_string(),
            });
        }
    }
    // ld.so.conf 及 ld.so.conf.d 下新增配置同样登记（弱信号）。
    for config in ["/etc/ld.so.conf"] {
        if let Some(content) = read_lossy(Path::new(config)) {
            rows.push(PersistenceMiscRow {
                kind: "ld_so_conf".to_string(),
                path: config.to_string(),
                detail: head_content(std::path::Path::new(config), 512),
                flag: if content.contains("/tmp") || content.contains("/dev/shm") {
                    "suspicious_path".to_string()
                } else {
                    String::new()
                },
            });
        }
    }
    if let Ok(entries) = fs::read_dir("/etc/ld.so.conf.d") {
        for entry in entries.flatten() {
            let file = entry.path();
            if file.to_string_lossy().ends_with(".conf") {
                rows.push(PersistenceMiscRow {
                    kind: "ld_so_conf".to_string(),
                    path: file.display().to_string(),
                    detail: head_content(&file, 256),
                    flag: String::new(),
                });
            }
        }
    }
}

fn collect_pam(rows: &mut Vec<PersistenceMiscRow>) {
    let Ok(entries) = fs::read_dir("/etc/pam.d") else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.path();
        let Some(content) = read_lossy(&file) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let module = fields[2];
            if module.starts_with('/') && !PAM_MODULE_DIRS.iter().any(|dir| module.starts_with(dir))
            {
                rows.push(PersistenceMiscRow {
                    kind: "pam_unusual_module".to_string(),
                    path: file.display().to_string(),
                    detail: truncate(trimmed, 200).to_string(),
                    flag: "high_signal".to_string(),
                });
            }
        }
    }
}

fn collect_tcp_wrappers(rows: &mut Vec<PersistenceMiscRow>) {
    for file in ["/etc/hosts.allow", "/etc/hosts.deny"] {
        let Some(content) = read_lossy(Path::new(file)) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            rows.push(PersistenceMiscRow {
                kind: "tcp_wrapper".to_string(),
                path: file.to_string(),
                detail: truncate(trimmed, 200).to_string(),
                flag: String::new(),
            });
        }
    }
}

fn collect_python_pth(rows: &mut Vec<PersistenceMiscRow>, errors: &mut Vec<CollectionError>) {
    for base in [
        "/usr/lib/python3",
        "/usr/local/lib/python3",
        "/usr/lib/python2.7",
    ] {
        let base_path = std::path::Path::new(base);
        if !base_path.exists() {
            continue;
        }
        let walk_stats = walk_dir_capped(base_path, |path, is_dir| {
            if is_dir {
                return true;
            }
            if path.extension().map(|ext| ext == "pth").unwrap_or(false) {
                let content = read_evidence_capped(path, "python_pth", errors);
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("import ") || trimmed.contains("exec(") {
                        rows.push(PersistenceMiscRow {
                            kind: "python_pth".to_string(),
                            path: path.display().to_string(),
                            detail: truncate(trimmed, 200).to_string(),
                            flag: "high_signal".to_string(),
                        });
                    }
                }
            }
            true
        });
        if walk_stats.failed_dirs > 0 {
            errors.push(super::collection_error(
                "persistence_misc",
                base,
                "walk_dir_capped",
                format!(
                    "{} director(y/ies) under {base} could not be read (permission or removed mid-scan); .pth coverage may be incomplete",
                    walk_stats.failed_dirs
                ),
                None,
            ));
        }
    }
}

fn collect_motd(rows: &mut Vec<PersistenceMiscRow>) {
    let mut files = vec![
        "/etc/motd".to_string(),
        "/etc/profile".to_string(),
        "/etc/bash.bashrc".to_string(),
        "/etc/bashrc".to_string(),
    ];
    if let Ok(entries) = fs::read_dir("/etc/update-motd.d") {
        files.extend(entries.flatten().filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_file())
                .map(|_| entry.path().display().to_string())
        }));
    }
    for (_user, home, _shell) in super::passwd_entries() {
        for name in [".profile", ".bashrc", ".bash_profile", ".bash_logout"] {
            files.push(home.join(name).display().to_string());
        }
    }
    files.extend(
        ["/etc/skel/.profile", "/etc/skel/.bashrc"]
            .iter()
            .map(|value| value.to_string()),
    );
    for file in files {
        let Some(content) = read_lossy(Path::new(&file)) else {
            continue;
        };
        // 只登记含执行语义的行（motd 脚本/profile 注入）。
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if lower.contains("/tmp/")
                || lower.contains("curl")
                || lower.contains("wget")
                || lower.contains("base64")
                || lower.contains("nc -e")
                || lower.contains("/dev/tcp/")
            {
                rows.push(PersistenceMiscRow {
                    kind: "profile_or_motd_exec".to_string(),
                    path: file.clone(),
                    detail: truncate(trimmed, 200).to_string(),
                    flag: String::new(),
                });
            }
        }
    }
}

/// 读取持久化证据文件（systemd unit/.timer、.desktop、.pth 等）：
/// - 2MB take 上限：超限只保留前 MAX_FILE_BYTES 字节并登记 CollectionError，
///   不再无上限整读或因超限静默返回空；
/// - lossy 解码：GBK 等非 UTF-8 内容保留证据（U+FFFD 替换无效字节）。
fn read_evidence_capped(
    path: &Path,
    kind: &str,
    errors: &mut Vec<CollectionError>,
) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut limited = file.take(MAX_FILE_BYTES + 1);
    let mut bytes = Vec::new();
    if limited.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    if bytes.len() as u64 > MAX_FILE_BYTES {
        bytes.truncate(MAX_FILE_BYTES as usize);
        errors.push(super::collection_error(
            "persistence_misc",
            path.display().to_string(),
            format!("read_{kind}"),
            "persistence file exceeded the 2MB read cap; only the first 2MB was retained",
            None,
        ));
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 读取配置类文件并 lossy 解码：GBK 等非 UTF-8 内容保留证据。
fn read_lossy(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// 预览式读取：2MB take 上限 + lossy 解码后截断到 max 字符。
fn head_content(path: &std::path::Path, max: usize) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_FILE_BYTES);
    if limited.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    truncate(String::from_utf8_lossy(&bytes).trim(), max).to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_columns_stable() {
        assert_eq!(HEADER.split(',').count(), 4);
    }

    #[test]
    fn evidence_read_truncates_at_2mb_cap_and_registers_error() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-persist-cap-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("evil.service");
        let mut content = b"[Service]\nExecStart=/tmp/x\n".to_vec();
        content.resize(MAX_FILE_BYTES as usize + 1024, b'A');
        fs::write(&path, &content).unwrap();
        let mut errors = Vec::new();
        let text = read_evidence_capped(&path, "user_systemd", &mut errors);
        assert_eq!(text.len(), MAX_FILE_BYTES as usize);
        assert!(text.contains("ExecStart=/tmp/x"));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("2MB"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_read_retains_gbk_content_lossily() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-persist-gbk-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("backdoor.desktop");
        // GBK 编码的命令注释 + ExecStart：严格 UTF-8 读取会整文件丢弃。
        fs::write(&path, b"[Desktop Entry]\nExec=/tmp/\xd6\xd0\xce\xc4.sh\n").unwrap();
        let mut errors = Vec::new();
        let text = read_evidence_capped(&path, "xdg_autostart", &mut errors);
        assert!(text.contains("Exec=/tmp/"));
        assert!(errors.is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
    }
}
