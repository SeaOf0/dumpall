//! 单项导出模式（`dumpall export <logs|tasks|net|proc>`）。
//!
//! 设计约定：参数跨平台完全一致，导出内容自动对应当前系统——
//! Windows 上 logs 导出 EVTX 事件日志、tasks 导出计划任务、net/proc 走 Windows 采集器；
//! Linux 上 logs 导出 /var/log 全量（含轮转）、tasks 导出 cron/systemd/rc、net/proc 走 /proc 采集器。
//! 支持与全局一致的时间参数：logs 的解析事件按 --since/--until 过滤。

use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

use sha2::Digest;

use crate::cli::ExportKind;
use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers::{self, RunLogger};

/// 原始日志复制的单文件/数量/总量上限。
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 3_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub fn execute_export_run(
    resolved: ResolvedRun,
    what: ExportKind,
    raw_args: Vec<String>,
) -> Result<()> {
    let _preflight = crate::preflight::run_preflight();
    let layout = OutputLayout::create(&resolved.output_dir)?;
    let mut logger = RunLogger::create(&layout.run_log, resolved.safety.verbose)?;
    logger.log("run started (export)")?;
    logger.log(format!("export kind: {}", kind_name(what)))?;

    let mut errors: Vec<CollectionError> = Vec::new();
    match what {
        ExportKind::Proc => {
            export_proc(resolved_ref(&resolved), &layout, &mut logger, &mut errors)?
        }
        ExportKind::Net => export_net(resolved_ref(&resolved), &layout, &mut logger, &mut errors)?,
        ExportKind::Tasks => {
            export_tasks(resolved_ref(&resolved), &layout, &mut logger, &mut errors)?
        }
        ExportKind::Logs => {
            export_logs(resolved_ref(&resolved), &layout, &mut logger, &mut errors)?
        }
    }

    if !errors.is_empty() {
        writers::write_collection_errors(&layout.collection_errors, &errors)?;
    }
    let range = time_range_summary(&resolved);
    let manifest = serde_json::json!({
        "tool": "dumpall",
        "mode": "export",
        "kind": kind_name(what),
        "time_range": range,
        "os": std::env::consts::OS,
        "output_dir": layout.root.display().to_string(),
        "raw_args": raw_args,
        "collection_errors": errors.len(),
    });
    writers::write_json_pretty(&layout.manifest, &manifest)?;

    let merged_xlsx_path = layout.reports_dir.join("dumpall_report.xlsx");
    let mut merged_report_note = String::from("未启用");
    let sheets = if resolved.xlsx_report {
        match crate::output::xlsx_report::write_merged_xlsx(&layout) {
            Ok(count) => {
                merged_report_note = merged_xlsx_path.display().to_string();
                count
            }
            Err(error) => {
                // 与 lib.rs 主流程一致：失败明确说明，不再静默当作 0 并照常打印路径。
                let message = format!("report: merged xlsx workbook failed: {error}");
                logger.log(&message)?;
                println!("{message}");
                merged_report_note = "生成失败（见上方说明与运行日志）".to_string();
                0
            }
        }
    } else {
        0
    };
    logger.log(format!(
        "export finished: {} collection error(s), merged xlsx sheet(s): {sheets}",
        errors.len()
    ))?;
    println!(
        "export [{}] 完成：{}（{} 个采集错误）\n合并报告：{}",
        kind_name(what),
        layout.root.display(),
        errors.len(),
        merged_report_note
    );
    Ok(())
}

fn resolved_ref(resolved: &ResolvedRun) -> &ResolvedRun {
    resolved
}

fn kind_name(what: ExportKind) -> &'static str {
    match what {
        ExportKind::Logs => "logs",
        ExportKind::Tasks => "tasks",
        ExportKind::Net => "net",
        ExportKind::Proc => "proc",
    }
}

fn time_range_summary(resolved: &ResolvedRun) -> serde_json::Value {
    serde_json::json!({
        "since": resolved.time_range.since,
        "until": resolved.time_range.until,
        "hours": resolved.time_range.hours,
    })
}

fn export_proc(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    logger.log("export: processes")?;
    crate::collectors::process::collect(layout, errors, resolved.safety.redact)?;
    #[cfg(unix)]
    {
        logger.log("export: process environment")?;
        crate::collectors::host_artifacts::env_collect::collect(
            layout,
            errors,
            resolved.safety.redact,
        )?;
    }
    Ok(())
}

fn export_net(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    logger.log("export: network connections")?;
    crate::collectors::network::collect(layout, errors, resolved.safety.redact)?;
    #[cfg(unix)]
    {
        logger.log("export: network extras (arp/unix/dns/firewall)")?;
        crate::collectors::host_artifacts::net_ext::collect(layout, errors)?;
    }
    #[cfg(windows)]
    {
        logger.log("export: network extras (dns/shares/firewall)")?;
        crate::collectors::host_artifacts::win_ext::collect_network(layout, errors)?;
    }
    Ok(())
}

fn export_tasks(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    logger.log("export: scheduled tasks / startup / services")?;
    crate::collectors::persistence::collect(layout, errors, resolved.safety.redact)?;
    // 原始任务/启动面文件副本（平台对应）。
    let mut manifest_rows: Vec<RawManifestRow> = Vec::new();
    let mut total_bytes = 0u64;
    let sources: Vec<std::path::PathBuf> = task_raw_sources();
    for source in sources {
        if source.is_file() {
            copy_raw_file(&source, layout, &mut manifest_rows, &mut total_bytes, errors);
        } else if source.is_dir() {
            copy_raw_dir(&source, layout, &mut manifest_rows, &mut total_bytes, errors);
        }
    }
    write_raw_manifest(layout, &manifest_rows, "tasks")?;
    Ok(())
}

#[cfg(unix)]
fn task_raw_sources() -> Vec<std::path::PathBuf> {
    [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/etc/systemd/system",
        "/etc/rc.local",
        "/etc/init.d",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect()
}

#[cfg(windows)]
fn task_raw_sources() -> Vec<std::path::PathBuf> {
    let mut sources = vec![
        std::path::PathBuf::from(r"C:\Windows\System32\Tasks"),
        std::path::PathBuf::from(r"C:\Windows\SysWOW64\Tasks"),
    ];
    if let Some(profile) = std::env::var_os("APPDATA") {
        sources.push(
            std::path::Path::new(&profile)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }
    sources.push(std::path::PathBuf::from(
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ));
    sources
}

#[cfg(not(any(unix, windows)))]
fn task_raw_sources() -> Vec<std::path::PathBuf> {
    Vec::new()
}

fn export_logs(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    // 1) 附加平台默认事件源（logs 导出不依赖 profile）。
    let mut resolved = resolved.clone();
    let (evtx, journal, audit) =
        crate::config::default_host_event_paths(crate::profile::ScanProfile::HostIr);
    if resolved.evtx_paths.is_empty() {
        resolved.evtx_paths = evtx;
    }
    if resolved.journal_paths.is_empty() {
        resolved.journal_paths = journal;
    }
    if resolved.audit_log_paths.is_empty() {
        resolved.audit_log_paths = audit;
    }

    // 2) 原始日志复制（平台对应：Linux /var/log 全量；Windows EVTX 通道）。
    logger.log("export: raw log copy")?;
    let mut manifest_rows: Vec<RawManifestRow> = Vec::new();
    let mut total_bytes = 0u64;
    let roots: Vec<std::path::PathBuf> = log_raw_roots();
    for root in roots {
        if root.is_file() {
            copy_raw_file(&root, layout, &mut manifest_rows, &mut total_bytes, errors);
        } else if root.is_dir() {
            copy_raw_dir(&root, layout, &mut manifest_rows, &mut total_bytes, errors);
        }
    }
    write_raw_manifest(layout, &manifest_rows, "logs")?;

    // 3) 事件解析（auth/audit/EVTX）。
    logger.log("export: event parsing")?;
    if let Err(error) = crate::collectors::events::collect(&resolved, layout, logger) {
        errors.push(crate::collectors::collection_error(
            "export_logs",
            "events",
            "collect",
            "event collection failed",
            Some(error.to_string()),
        ));
    }

    // 4) 时间范围过滤（--since/--until/-t 应用于解析事件）。
    filter_events_by_range(layout, &resolved, logger)?;
    Ok(())
}

#[cfg(unix)]
fn log_raw_roots() -> Vec<std::path::PathBuf> {
    vec![std::path::PathBuf::from("/var/log")]
}

#[cfg(windows)]
fn log_raw_roots() -> Vec<std::path::PathBuf> {
    // EVTX 通道目录 + 用户显式指定的 --log-path 由通用复制覆盖。
    // SystemRoot 常为 C:\Windows，与硬编码路径重复，规整后去重。
    let mut roots = Vec::new();
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        roots.push(
            std::path::Path::new(&system_root)
                .join("System32")
                .join("winevt")
                .join("Logs"),
        );
    }
    roots.push(std::path::PathBuf::from(r"C:\Windows\System32\winevt\Logs"));
    dedup_roots(roots)
}

/// 字符串规整去重（保留首次出现顺序）：统一分隔符与尾部斜杠；
/// Windows 文件名大小写不敏感，按小写比较。
#[cfg_attr(not(windows), allow(dead_code))]
fn dedup_roots(roots: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut seen = std::collections::BTreeSet::new();
    roots
        .into_iter()
        .filter(|root| {
            let key = root.display().to_string().replace('/', "\\");
            let key = key.trim_end_matches('\\').to_string();
            #[cfg(windows)]
            let key = key.to_lowercase();
            seen.insert(key)
        })
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn log_raw_roots() -> Vec<std::path::PathBuf> {
    Vec::new()
}

/// raw_manifest.csv 数据行。
struct RawManifestRow {
    source_path: String,
    relative_path: String,
    size_bytes: u64,
    sha256: String,
    mtime: String,
}

fn copy_raw_dir(
    root: &Path,
    layout: &OutputLayout,
    manifest: &mut Vec<RawManifestRow>,
    total_bytes: &mut u64,
    errors: &mut Vec<CollectionError>,
) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if manifest.len() >= MAX_FILES || *total_bytes >= MAX_TOTAL_BYTES {
            return;
        }
        if depth > 8 {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            if manifest.len() >= MAX_FILES || *total_bytes >= MAX_TOTAL_BYTES {
                return;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            copy_raw_file(&path, layout, manifest, total_bytes, errors);
        }
    }
}

fn copy_raw_file(
    source: &Path,
    layout: &OutputLayout,
    manifest: &mut Vec<RawManifestRow>,
    total_bytes: &mut u64,
    errors: &mut Vec<CollectionError>,
) {
    let Ok(metadata) = fs::metadata(source) else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    let remaining = MAX_TOTAL_BYTES.saturating_sub(*total_bytes);
    // 超限跳过必须留痕：记录到 collection_errors，不允许静默无副本。
    if metadata.len() > MAX_FILE_BYTES {
        errors.push(crate::collectors::collection_error(
            "export_raw_copy",
            source.display().to_string(),
            "copy",
            "skipped_over_size",
            Some(format!(
                "file is {} bytes; per-file copy limit is {} bytes",
                metadata.len(),
                MAX_FILE_BYTES
            )),
        ));
        return;
    }
    if metadata.len() > remaining {
        errors.push(crate::collectors::collection_error(
            "export_raw_copy",
            source.display().to_string(),
            "copy",
            "skipped_over_budget",
            Some(format!(
                "file is {} bytes; remaining total copy budget is {} bytes",
                metadata.len(),
                remaining
            )),
        ));
        return;
    }
    let relative = crate::collectors::host_artifacts::raw_copy::sanitize_relative_public(source);
    let destination = layout.raw_dir.join(&relative);
    if let Some(parent) = destination.parent() {
        let _ = fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let temp = destination.with_extension("part");
    let Ok(mut input) = File::open(source) else {
        return;
    };
    let Ok(mut output) = File::create(&temp) else {
        return;
    };
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut copied = 0u64;
    let copy_ok = loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(_) => break false,
        };
        if read == 0 {
            break true;
        }
        if copied.saturating_add(read as u64) > remaining {
            break false;
        }
        if output.write_all(&buffer[..read]).is_err() {
            break false;
        }
        hasher.update(&buffer[..read]);
        copied += read as u64;
    };
    drop(output);
    drop(input);
    if !copy_ok || fs::rename(&temp, &destination).is_err() {
        let _ = fs::remove_file(&temp);
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&destination, fs::Permissions::from_mode(0o600));
    }
    let hash = format!("{:x}", hasher.finalize());
    *total_bytes += copied;
    manifest.push(RawManifestRow {
        source_path: source.display().to_string(),
        relative_path: relative.display().to_string(),
        size_bytes: copied,
        sha256: hash,
        mtime: metadata
            .modified()
            .ok()
            .map(crate::time_utils::system_time_to_iso)
            .unwrap_or_default(),
    });
}

fn write_raw_manifest(layout: &OutputLayout, rows: &[RawManifestRow], kind: &str) -> Result<()> {
    let manifest = layout.raw_dir.join("raw_manifest.csv");
    if let Some(parent) = manifest.parent() {
        fs::create_dir_all(parent)?;
    }
    // 路径/文件名来自被检主机文件系统（可能以 = + - @ 开头），经 csv::Writer
    // 正确引用并套公式注入防护，杜绝手拼 CSV 串列/注入。
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&manifest)?;
    writer.write_record(["source_path", "relative_path", "size", "sha256", "mtime"])?;
    for row in rows {
        let size = row.size_bytes.to_string();
        writer.write_record([
            crate::output::writers::csv_safe_cell(&row.source_path).as_str(),
            crate::output::writers::csv_safe_cell(&row.relative_path).as_str(),
            size.as_str(),
            row.sha256.as_str(),
            row.mtime.as_str(),
        ])?;
    }
    writer.flush()?;
    println!(
        "export[{}]: 原始文件副本 {} 个 → {}",
        kind,
        rows.len(),
        manifest.display()
    );
    Ok(())
}

/// 按时间范围过滤事件产物：windows/linux_events.jsonl 的 timestamp 字段，
/// auth_events.csv 的 timestamp 列。窗口来源与采集一致：--since/--until 优先，
/// 否则 --log-days（默认 30 天）；--full-scan 不过滤。任一边界存在即生效
/// （仅 since 剔除更早事件，仅 until 剔除更晚事件），与参数语义一致。
fn filter_events_by_range(
    layout: &OutputLayout,
    resolved: &ResolvedRun,
    logger: &mut RunLogger,
) -> Result<()> {
    let since = resolved
        .event_cutoff
        .as_deref()
        .and_then(|value| crate::time_utils::parse_datetime(value).ok());
    let until = resolved
        .time_range
        .until
        .as_deref()
        .filter(|_| !resolved.full_scan)
        .and_then(|value| crate::time_utils::parse_datetime(value).ok());
    if since.is_none() && until.is_none() {
        return Ok(());
    }
    let kept = filter_jsonl_by_time(&layout.windows_events, "timestamp", since, until)
        + filter_jsonl_by_time(&layout.linux_events, "timestamp", since, until)
        + filter_csv_by_time(&layout.auth_events, "timestamp", since, until);
    let describe = |bound: Option<time::OffsetDateTime>| {
        bound
            .map(|value| crate::time_utils::format_iso(value))
            .unwrap_or_else(|| "-".to_string())
    };
    logger.log(format!(
        "export: time filter [{} ~ {}] kept {kept} event row(s)",
        describe(since),
        describe(until)
    ))?;
    Ok(())
}

fn parse_time(value: &str) -> Option<time::OffsetDateTime> {
    crate::time_utils::parse_datetime(value).ok()
}

/// 时间戳命中判定：只应用存在的边界（since 剔除更早，until 剔除更晚）。
fn in_time_range(
    stamp: time::OffsetDateTime,
    since: Option<time::OffsetDateTime>,
    until: Option<time::OffsetDateTime>,
) -> bool {
    since.map_or(true, |since| stamp >= since) && until.map_or(true, |until| stamp <= until)
}

fn filter_jsonl_by_time(
    path: &Path,
    field: &str,
    since: Option<time::OffsetDateTime>,
    until: Option<time::OffsetDateTime>,
) -> usize {
    let Ok(file) = fs::File::open(path) else {
        return 0;
    };
    let temp = path.with_extension("filtered.part");
    let Ok(output) = fs::File::create(&temp) else {
        return 0;
    };
    let mut writer = BufWriter::new(output);
    let mut kept = 0usize;
    for line in BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if line.trim().is_empty() {
            continue;
        }
        let keep = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .and_then(|value| {
                value
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .and_then(|stamp| parse_time(&stamp))
            .map(|stamp| in_time_range(stamp, since, until))
            .unwrap_or(true);
        if keep {
            if writeln!(writer, "{line}").is_err() {
                let _ = fs::remove_file(&temp);
                return 0;
            }
            kept += 1;
        }
    }
    if writer.flush().is_err() || fs::rename(&temp, path).is_err() {
        let _ = fs::remove_file(&temp);
        return 0;
    }
    kept
}

fn filter_csv_by_time(
    path: &Path,
    column: &str,
    since: Option<time::OffsetDateTime>,
    until: Option<time::OffsetDateTime>,
) -> usize {
    let Ok(file) = fs::File::open(path) else {
        return 0;
    };
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(BufReader::new(file));
    let Ok(headers) = reader.headers() else {
        return 0;
    };
    let headers = headers.clone();
    let Some(index) = headers.iter().position(|h| h == column) else {
        return 0;
    };
    let temp = path.with_extension("filtered.part");
    let Ok(output) = fs::File::create(&temp) else {
        return 0;
    };
    let mut writer = csv::Writer::from_writer(BufWriter::new(output));
    if writer.write_record(&headers).is_err() {
        let _ = fs::remove_file(&temp);
        return 0;
    }
    let mut kept = 0usize;
    for record in reader.records().flatten() {
        let keep = record
            .get(index)
            .and_then(parse_time)
            .map(|stamp| in_time_range(stamp, since, until))
            .unwrap_or(true);
        if keep {
            if writer.write_record(&record).is_err() {
                let _ = fs::remove_file(&temp);
                return 0;
            }
            kept += 1;
        }
    }
    if writer.flush().is_err() || fs::rename(&temp, path).is_err() {
        let _ = fs::remove_file(&temp);
        return 0;
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonl_time_filter_keeps_only_range() {
        let dir = std::env::temp_dir().join(format!("dumpall-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        std::fs::write(
            &path,
            "{\"timestamp\":\"2026-08-01T00:00:00+08:00\",\"a\":1}\n{\"timestamp\":\"2026-08-20T00:00:00+08:00\",\"a\":2}\n",
        )
        .unwrap();
        let since = crate::time_utils::parse_datetime("2026-08-10T00:00:00+08:00").unwrap();
        let until = crate::time_utils::parse_datetime("2026-08-31T00:00:00+08:00").unwrap();
        let kept = filter_jsonl_by_time(&path, "timestamp", Some(since), Some(until));
        assert_eq!(kept, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("2026-08-20"));
        assert!(!content.contains("2026-08-01T00:00:00"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn jsonl_time_filter_with_only_since_still_applies() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-export-since-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        std::fs::write(
            &path,
            "{\"timestamp\":\"2026-08-01T00:00:00+08:00\",\"a\":1}\n{\"timestamp\":\"2026-08-20T00:00:00+08:00\",\"a\":2}\n",
        )
        .unwrap();
        // 仅 since：剔除更早事件，无上界。
        let since = crate::time_utils::parse_datetime("2026-08-10T00:00:00+08:00").unwrap();
        let kept = filter_jsonl_by_time(&path, "timestamp", Some(since), None);
        assert_eq!(kept, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("2026-08-20"));
        assert!(!content.contains("2026-08-01T00:00:00"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn csv_time_filter_drops_out_of_range_rows() {
        let dir = std::env::temp_dir().join(format!("dumpall-export-csv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("auth.csv");
        std::fs::write(
            &path,
            "event_id,timestamp,user\n4625,2026-08-01T10:00:00+08:00,bob\n4624,2026-08-20T10:00:00+08:00,alice\n",
        )
        .unwrap();
        let since = crate::time_utils::parse_datetime("2026-08-15T00:00:00+08:00").unwrap();
        let until = crate::time_utils::parse_datetime("2026-08-31T00:00:00+08:00").unwrap();
        let kept = filter_csv_by_time(&path, "timestamp", Some(since), Some(until));
        assert_eq!(kept, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("alice"));
        assert!(!content.contains("bob"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn csv_time_filter_with_only_until_still_applies() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-export-until-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("auth.csv");
        std::fs::write(
            &path,
            "event_id,timestamp,user\n4625,2026-08-01T10:00:00+08:00,bob\n4624,2026-08-20T10:00:00+08:00,alice\n",
        )
        .unwrap();
        // 仅 until：剔除更晚事件，无下界。
        let until = crate::time_utils::parse_datetime("2026-08-15T00:00:00+08:00").unwrap();
        let kept = filter_csv_by_time(&path, "timestamp", None, Some(until));
        assert_eq!(kept, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("bob"));
        assert!(!content.contains("alice"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dedup_roots_removes_duplicate_and_trailing_slash_variants() {
        let roots = vec![
            std::path::PathBuf::from("/var/log/"),
            std::path::PathBuf::from("/var/log"),
            std::path::PathBuf::from("/var/log/audit"),
        ];
        let deduped = dedup_roots(roots);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0], std::path::PathBuf::from("/var/log/"));
        assert_eq!(deduped[1], std::path::PathBuf::from("/var/log/audit"));
    }

    #[test]
    fn copy_raw_file_records_over_budget_skip_in_collection_errors() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-export-budget-{}",
            std::process::id()
        ));
        let layout = OutputLayout::from_root(dir.join("results"));
        std::fs::create_dir_all(&layout.raw_dir).unwrap();
        let source = dir.join("small.log");
        std::fs::write(&source, b"data").unwrap();
        let mut manifest = Vec::new();
        let mut errors = Vec::new();
        // 预算耗尽：remaining = 0 → skipped_over_budget。
        let mut total_bytes = MAX_TOTAL_BYTES;
        copy_raw_file(
            &source,
            &layout,
            &mut manifest,
            &mut total_bytes,
            &mut errors,
        );
        assert!(manifest.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "skipped_over_budget");
        assert_eq!(errors[0].path, source.display().to_string());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn raw_manifest_wraps_formula_prefixed_paths() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-export-manifest-{}",
            std::process::id()
        ));
        let layout = OutputLayout::from_root(dir.join("results"));
        std::fs::create_dir_all(&layout.raw_dir).unwrap();
        let rows = vec![RawManifestRow {
            source_path: "=HYPERLINK(\"http://evil\")".to_string(),
            relative_path: "-cmd".to_string(),
            size_bytes: 3,
            sha256: "abc123".to_string(),
            mtime: "2026-08-27T00:00:00+08:00".to_string(),
        }];
        write_raw_manifest(&layout, &rows, "logs").unwrap();
        let content = std::fs::read_to_string(layout.raw_dir.join("raw_manifest.csv")).unwrap();
        assert!(content.contains("'=HYPERLINK"));
        assert!(content.contains(",-cmd") || content.contains(",'-cmd"));
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_path(layout.raw_dir.join("raw_manifest.csv"))
            .unwrap();
        let records: Vec<csv::StringRecord> = reader.records().flatten().collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].get(0), Some("'=HYPERLINK(\"http://evil\")"));
        assert_eq!(records[0].get(1), Some("'-cmd"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
