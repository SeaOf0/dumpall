//! 主机痕迹采集扩展（triage 层）：历史命令、SSH/ sudo 配置、登录记录、
//! 内核模块、网络补充信息、SUID/临时目录扫描、进程环境变量、持久化深挖，
//! 以及 Windows 注册表持久化/WMI 订阅/驱动清单等。账户安全/隐藏账户
//! 检查属于基础采集阶段，由 `collectors::run_basic_collection` 始终执行。
//!
//! 所有采集保持只读：不修改系统状态，不执行破坏性命令。

pub mod evidence_copy;
#[cfg(unix)]
pub mod memdump;
pub mod memory;
pub mod memstrings;
#[cfg(target_os = "linux")]
pub mod memtriage;
pub mod raw_copy;

#[cfg(unix)]
pub mod env_collect;
#[cfg(unix)]
pub mod fs_ext;
#[cfg(unix)]
pub mod kernel;
#[cfg(unix)]
pub mod linux_ext;
#[cfg(unix)]
pub mod login_records;
#[cfg(unix)]
pub mod net_ext;
#[cfg(unix)]
pub mod persistence_ext;
#[cfg(unix)]
pub mod shell_history;
#[cfg(unix)]
pub mod ssh;
#[cfg(unix)]
pub mod sudo;
#[cfg(unix)]
pub mod volatile_ext;

/// 回收站 $I 纯字节解析：无平台 API 依赖，跨平台编译以便单元测试。
#[cfg(any(windows, test))]
pub mod dollar_i;

#[cfg(windows)]
pub mod win_artifacts;
#[cfg(windows)]
pub mod win_ext;
#[cfg(windows)]
pub mod win_memdump;
#[cfg(windows)]
pub mod win_registry;
#[cfg(windows)]
pub mod win_wmi;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers::RunLogger;

use super::collection_error;

/// host artifacts 阶段单目录遍历的最大深度。
#[cfg(unix)]
const MAX_WALK_DEPTH: usize = 8;
/// host artifacts 阶段单次遍历最大文件数上限。
#[cfg(unix)]
const MAX_WALK_FILES: usize = 100_000;

#[derive(Debug, Default)]
pub struct HostArtifactsReport {
    pub errors: Vec<CollectionError>,
    pub files_scanned: u64,
    pub notes: Vec<String>,
}

pub fn collect(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<HostArtifactsReport> {
    let mut report = HostArtifactsReport::default();

    #[cfg(unix)]
    {
        logger.log("host artifacts: shell history")?;
        shell_history::collect(layout, &mut report.errors, resolved.safety.redact)?;

        logger.log("host artifacts: ssh keys and sshd config")?;
        ssh::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: sudoers")?;
        sudo::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: login records (wtmp/btmp/lastlog)")?;
        let login_rows = login_records::collect(layout, &mut report.errors)?;
        report.notes.push(format!(
            "host artifacts: {} login history record(s) parsed from wtmp/btmp/lastlog.",
            login_rows
        ));

        logger.log("host artifacts: kernel modules")?;
        kernel::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: network extras (arp/unix/dns/firewall)")?;
        net_ext::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: filesystem extras (suid/temp/deleted-open)")?;
        let fs_stats = fs_ext::collect(
            resolved,
            layout,
            &mut report.errors,
            recent_file_window_days(resolved),
        )?;
        report.files_scanned += fs_stats.files_scanned;

        logger.log("host artifacts: process environment")?;
        env_collect::collect(layout, &mut report.errors, resolved.safety.redact)?;

        logger.log("host artifacts: extended volatile process context")?;
        volatile_ext::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: persistence extras")?;
        persistence_ext::collect(layout, &mut report.errors)?;

        logger.log(
            "host artifacts: linux extras (kernel params/accounts/rc/caps/integrity/hidden-proc)",
        )?;
        linux_ext::collect(layout, &mut report.errors)?;
    }

    #[cfg(windows)]
    {
        let _ = resolved;
        logger.log("host artifacts: registry persistence")?;
        win_registry::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: wmi subscriptions")?;
        win_wmi::collect(layout, &mut report.errors)?;

        logger.log("host artifacts: windows extras (drivers/dns/shares/firewall)")?;
        win_ext::collect(layout, &mut report.errors)?;

        logger.log(
            "host artifacts: windows artifacts (hives/recycle/lnk/bits/alias/sdb/user dirs)",
        )?;
        win_artifacts::collect(layout, &mut report.errors)?;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (resolved, logger);
        report
            .notes
            .push("host artifacts: unsupported platform, skipped.".to_string());
    }

    report.notes.push(format!(
        "host artifacts stage completed: {} collection error(s).",
        report.errors.len()
    ));
    Ok(report)
}

/// 从事件窗口派生"近期文件"筛选天数：
/// - full_scan → None（不按时间筛，全量登记）；
/// - event_cutoff 存在（--since 或 --log-days 推算）→ 用其距今的天数（向上取整）；
/// - 无窗口信息 → 30 天（与历史默认一致，保持向后兼容）。
#[cfg(unix)]
fn recent_file_window_days(resolved: &ResolvedRun) -> Option<i64> {
    if resolved.full_scan {
        return None;
    }
    let fallback = Some(fs_ext::DEFAULT_RECENT_FILE_WINDOW_DAYS);
    let Some(cutoff) = resolved.event_cutoff.as_deref() else {
        return fallback;
    };
    match crate::time_utils::parse_datetime(cutoff) {
        Ok(cutoff_time) => {
            let elapsed_seconds = (crate::time_utils::now() - cutoff_time)
                .whole_seconds()
                .max(0);
            Some((elapsed_seconds + 86_399) / 86_400)
        }
        Err(_) => fallback,
    }
}

/// 通用目录遍历：深度受限、数量受限、跳过符号链接。
/// 返回访问的文件/目录条目数量、数量上限溢出标记与 read_dir 失败目录数。
#[cfg(unix)]
pub(crate) struct WalkStats {
    pub visited: usize,
    pub overflow: bool,
    pub failed_dirs: usize,
}

#[cfg(unix)]
pub(crate) fn walk_dir_capped(
    root: &std::path::Path,
    mut visitor: impl FnMut(&std::path::Path, bool) -> bool,
) -> WalkStats {
    let mut stats = WalkStats {
        visited: 0,
        overflow: false,
        failed_dirs: 0,
    };
    walk_recursive(root, 0, &mut visitor, &mut stats);
    stats
}

#[cfg(unix)]
fn walk_recursive(
    dir: &std::path::Path,
    depth: usize,
    visitor: &mut dyn FnMut(&std::path::Path, bool) -> bool,
    stats: &mut WalkStats,
) {
    if depth > MAX_WALK_DEPTH || stats.visited >= MAX_WALK_FILES {
        stats.overflow = stats.visited >= MAX_WALK_FILES;
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // read_dir 失败不再静默：累计失败目录数，由调用方汇总登记一条
        // CollectionError（避免逐目录刷屏）。
        Err(_) => {
            stats.failed_dirs += 1;
            return;
        }
    };
    for entry in entries.flatten() {
        if stats.visited >= MAX_WALK_FILES {
            stats.overflow = true;
            return;
        }
        let path = entry.path();
        let is_dir = match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(_) => false,
        };
        stats.visited += 1;
        if !visitor(&path, is_dir) {
            continue;
        }
        if is_dir {
            walk_recursive(&path, depth + 1, visitor, stats);
        }
    }
}

/// 本地 /etc/passwd 最小解析：返回 (用户名, 家目录, shell)。
#[cfg(unix)]
pub(crate) fn passwd_entries() -> Vec<(String, std::path::PathBuf, String)> {
    let mut entries = Vec::new();
    let Ok(content) = std::fs::read_to_string("/etc/passwd") else {
        return entries;
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 7 && !fields[0].is_empty() {
            entries.push((
                fields[0].to_string(),
                std::path::PathBuf::from(fields[5]),
                fields[6].to_string(),
            ));
        }
    }
    entries
}

/// 极简 which：按 PATH 探测可执行文件是否存在（白名单命令前置检查）。
#[cfg(unix)]
pub(crate) fn which(program: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path_env = std::env::var_os("PATH")?;
    // 采集器以 root 运行时，不从用户所有或可写 PATH 目录执行外部工具。
    let require_root_owner = unsafe {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        geteuid() == 0
    };
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(program);
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o022 != 0
            || (require_root_owner && metadata.uid() != 0)
        {
            continue;
        }
        let mut parent = dir.as_path();
        let mut trusted_parent = true;
        loop {
            let Ok(parent_meta) = std::fs::metadata(parent) else {
                trusted_parent = false;
                break;
            };
            if parent_meta.permissions().mode() & 0o022 != 0
                || (require_root_owner && parent_meta.uid() != 0)
            {
                trusted_parent = false;
                break;
            }
            let Some(next) = parent.parent() else {
                break;
            };
            if next == parent {
                break;
            }
            parent = next;
        }
        if !trusted_parent {
            continue;
        }
        return Some(candidate);
    }
    None
}

/// 原生内存获取的平台分发：Linux 物理内存（LiME），Windows 全进程内存转储。
pub fn native_memory_acquire(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
) -> crate::error::Result<String> {
    #[cfg(unix)]
    {
        memdump::acquire_native(resolved, layout)
    }
    #[cfg(windows)]
    {
        win_memdump::acquire_native(resolved, layout)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (resolved, layout);
        Err(crate::error::DumpallError::invalid_argument(
            "memory-dump",
            "native memory acquisition is not supported on this platform",
        ))
    }
}

/// 低影响进程内存取证：Linux 读取可疑 maps/mem 片段，Windows 采集受限进程 minidump。
pub fn process_memory_triage(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
) -> crate::error::Result<String> {
    #[cfg(target_os = "linux")]
    {
        memtriage::collect(resolved, layout)
    }
    #[cfg(windows)]
    {
        win_memdump::acquire_triage(resolved, layout)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (resolved, layout);
        Err(crate::error::DumpallError::invalid_argument(
            "memory-triage",
            "low-impact process memory triage is currently implemented for Linux; use Windows process minidumps or an external trusted collector",
        ))
    }
}

#[cfg(unix)]
pub(crate) fn push_collection_error(
    errors: &mut Vec<CollectionError>,
    source: &str,
    path: impl Into<String>,
    operation: &str,
    message: &str,
    detail: Option<String>,
) {
    errors.push(collection_error(source, path, operation, message, detail));
}
