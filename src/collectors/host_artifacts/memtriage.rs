//! Linux 低影响进程内存取证。
//!
//! 该模块不暂停进程、不 ptrace attach，也不读取物理内存。它先读取每个进程的
//! `/proc/<pid>/maps`，标记匿名可执行、可写可执行、deleted、tmpfs/memfd 和
//! Web 进程堆区，再以严格的单进程/全局预算读取少量 `/proc/<pid>/mem` 片段。
//! 这种方式可以捕获常见注入代码、内存马字符串和 deleted 映射，同时避免完整
//! RAM dump 对业务主机造成的磁盘、CPU 和暂停风险。

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::Path;

use serde::Serialize;

use crate::config::ResolvedRun;
use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;
use crate::output::writers;

const HEADER: &str =
    "pid,process,range,perms,path,size_bytes,reason,bytes_file,sha256,read_status\n";
const MAX_PROCESSES: usize = 4096;
const MAX_REGIONS: usize = 20_000;
const MAX_BYTES_PER_PROCESS: u64 = 8 * 1024 * 1024;
const MAX_BYTES_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_REGION_READ: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct MemoryTriageRow {
    pid: u32,
    process: String,
    range: String,
    perms: String,
    path: String,
    size_bytes: u64,
    reason: String,
    bytes_file: String,
    sha256: String,
    read_status: String,
}

#[derive(Debug, Clone)]
struct Mapping {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

pub fn collect(_resolved: &ResolvedRun, layout: &OutputLayout) -> Result<String> {
    let raw_dir = layout.raw_dir.join("memory_triage");
    fs::create_dir_all(&raw_dir)?;
    fs::set_permissions(&raw_dir, fs::Permissions::from_mode(0o700))?;

    let mut rows = Vec::new();
    let mut total_read = 0u64;
    let mut processes = 0usize;
    let mut regions = 0usize;
    let mut region_cap_hit = false;
    let proc_root = Path::new("/proc");
    let entries = fs::read_dir(proc_root).map_err(|error| {
        DumpallError::invalid_argument("memory-triage", format!("read /proc failed: {error}"))
    })?;

    for entry in entries.flatten() {
        if processes >= MAX_PROCESSES || regions >= MAX_REGIONS {
            if regions >= MAX_REGIONS {
                region_cap_hit = true;
            }
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let proc_dir = entry.path();
        let process = process_name(&proc_dir);
        let mappings = match parse_maps(&proc_dir.join("maps")) {
            Ok(value) => value,
            Err(_) => continue,
        };
        processes += 1;
        let mut process_read = 0u64;
        let mut mem = File::open(proc_dir.join("mem")).ok();
        for mapping in mappings {
            if regions >= MAX_REGIONS {
                region_cap_hit = true;
                break;
            }
            let Some(reason) = suspicious_reason(&mapping, &process) else {
                continue;
            };
            regions += 1;
            let size = mapping.end.saturating_sub(mapping.start);
            let mut row = MemoryTriageRow {
                pid,
                process: process.clone(),
                range: format!("0x{:x}-0x{:x}", mapping.start, mapping.end),
                perms: mapping.perms.clone(),
                path: mapping.path.clone(),
                size_bytes: size,
                reason: reason.to_string(),
                bytes_file: String::new(),
                sha256: String::new(),
                read_status: "metadata_only".to_string(),
            };

            let budget = MAX_BYTES_PER_PROCESS
                .saturating_sub(process_read)
                .min(MAX_BYTES_TOTAL.saturating_sub(total_read))
                .min(MAX_REGION_READ)
                .min(size);
            if budget > 0 {
                if let Some(file) = mem.as_mut() {
                    let mut bytes = vec![0u8; budget as usize];
                    match file.read_at(&mut bytes, mapping.start) {
                        Ok(read) if read > 0 => {
                            bytes.truncate(read);
                            let destination =
                                raw_dir.join(format!("{pid}_{:x}.bin", mapping.start));
                            if fs::write(&destination, &bytes).is_ok() {
                                let _ = fs::set_permissions(
                                    &destination,
                                    fs::Permissions::from_mode(0o600),
                                );
                                let hash = crate::parsers::access_log::sha256_hex(&bytes);
                                row.bytes_file = destination
                                    .strip_prefix(&layout.root)
                                    .unwrap_or(&destination)
                                    .display()
                                    .to_string();
                                row.sha256 = hash;
                                row.read_status = "captured".to_string();
                                process_read += read as u64;
                                total_read += read as u64;
                            } else {
                                row.read_status = "write_failed".to_string();
                            }
                        }
                        Ok(_) => row.read_status = "empty".to_string(),
                        Err(error) => row.read_status = format!("read_failed:{:?}", error.kind()),
                    }
                } else {
                    row.read_status = "mem_open_failed".to_string();
                }
            } else if total_read >= MAX_BYTES_TOTAL {
                row.read_status = "global_budget_exhausted".to_string();
            }
            rows.push(row);
            if total_read >= MAX_BYTES_TOTAL {
                break;
            }
        }
    }

    if rows.is_empty() {
        writers::write_text(&layout.memory_triage, HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.memory_triage, &rows)?;
    }
    // 区域/进程上限截断显式登记在摘要中（该阶段无 CollectionError 通道，
    // 摘要会进入运行 notes 与报告）。
    let cap_note = if region_cap_hit {
        format!(
            "; NOTE: suspicious-mapping registration reached the {MAX_REGIONS} region cap, later mappings were not recorded"
        )
    } else {
        String::new()
    };
    Ok(format!(
        "low-impact process memory triage: {processes} process(es), {regions} suspicious mapping(s), {total_read} bytes captured; no process suspension or ptrace attach{cap_note}"
    ))
}

fn process_name(proc_dir: &Path) -> String {
    fs::read_to_string(proc_dir.join("comm"))
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read(proc_dir.join("cmdline")).ok().map(|bytes| {
                String::from_utf8_lossy(&bytes)
                    .split('\0')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_maps(path: &Path) -> Result<Vec<Mapping>> {
    let file = File::open(path)?;
    let mut mappings = Vec::new();
    for line in BufReader::new(file).lines().take(MAX_REGIONS) {
        let line = line?;
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let Some(perms) = fields.next() else { continue };
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let path = fields.collect::<Vec<_>>().join(" ");
        if end > start {
            mappings.push(Mapping {
                start,
                end,
                perms: perms.to_string(),
                path,
            });
        }
    }
    Ok(mappings)
}

fn suspicious_reason(mapping: &Mapping, process: &str) -> Option<&'static str> {
    let path = mapping.path.to_ascii_lowercase();
    if mapping.perms.contains('x') && mapping.perms.contains('w') {
        return Some("writable_executable_mapping");
    }
    if path.contains("(deleted)")
        || path.contains("/tmp/")
        || path.contains("/dev/shm/")
        || path.starts_with("memfd:")
    {
        return Some("deleted_or_temp_executable_mapping");
    }
    if mapping.perms.contains('x') && mapping.path.is_empty() {
        return Some("anonymous_executable_mapping");
    }
    let web = [
        "nginx", "apache", "httpd", "php", "php-fpm", "java", "tomcat", "node", "w3wp", "dotnet",
        "gunicorn", "uwsgi", "python",
    ];
    if web
        .iter()
        .any(|token| process.to_ascii_lowercase().contains(token))
        && (mapping.path.is_empty() || mapping.path == "[heap]" || mapping.path == "[stack]")
        && mapping.perms.starts_with("rw")
    {
        return Some("web_process_anonymous_rw_mapping");
    }
    if mapping.path.is_empty() && mapping.perms.starts_with("rw") {
        return Some("anonymous_rw_mapping");
    }
    None
}
