//! 登录记录采集：原生解析 wtmp / btmp / lastlog 二进制记录（不依赖 last 命令）。
//!
//! glibc utmp 记录布局（384 字节，主机本机字节序）：
//! - 0:   u16 ut_type
//! - 4:   i32 ut_pid
//! - 8:   [u8;32] ut_line
//! - 40:  [u8;4]  ut_id
//! - 44:  [u8;32] ut_user
//! - 76:  [u8;256] ut_host
//! - 332: u16 e_termination, 334: u16 e_exit
//! - 336: i32 ut_session
//! - 340: i32 tv_sec, 344: i32 tv_usec
//! - 348: [u8;16] ut_addr_v6
//! - 364..384: 保留
//!
//! lastlog 记录：time_t(平台指针宽度决定 8/4 字节) + line[32] + host[256]。

use std::fs;
use std::io::Read;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const HEADER: &str = "source,record_type,user,terminal,host,address,pid,timestamp\n";
const WTMP_RECORD_SIZE: usize = 384;
/// wtmp/btmp/lastlog 单文件读取上限：先 metadata 预检，超限只 take 前 MAX 字节，
/// 防止 GB 级 btmp 整读打爆内存（截断会登记 CollectionError）。
const MAX_WTMP_BYTES: u64 = 64 * 1024 * 1024;
/// 单文件最大记录数，避免被巨型 wtmp 撑爆。
const MAX_RECORDS_PER_FILE: usize = 200_000;

const BOOT_TIME: u16 = 2;
const LOGIN_PROCESS: u16 = 6;
const USER_PROCESS: u16 = 7;
const DEAD_PROCESS: u16 = 8;
const RUN_LVL: u16 = 1;
const INIT_PROCESS: u16 = 5;
const SHUTDOWN_TIME: u16 = 11;

#[derive(Debug, Clone, Serialize)]
struct LoginRow {
    source: String,
    record_type: String,
    user: String,
    terminal: String,
    host: String,
    address: String,
    pid: String,
    timestamp: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<usize> {
    let mut rows = Vec::new();
    parse_wtmp_like("/var/log/wtmp", "wtmp", &mut rows, errors);
    parse_wtmp_like("/var/log/btmp", "btmp", &mut rows, errors);
    parse_lastlog(&mut rows, errors);
    if rows.is_empty() {
        writers::write_text(&layout.login_history, HEADER)?;
    } else {
        writers::write_csv_serialize(&layout.login_history, &rows)?;
    }
    Ok(rows.len())
}

fn parse_wtmp_like(
    path: &str,
    source: &str,
    rows: &mut Vec<LoginRow>,
    errors: &mut Vec<CollectionError>,
) {
    let Some(bytes) = read_login_file_capped(path, source, MAX_WTMP_BYTES, errors) else {
        return;
    };
    if bytes.len() < WTMP_RECORD_SIZE {
        if !bytes.is_empty() {
            errors.push(super::collection_error(
                "login_records",
                path,
                "size_check",
                "file smaller than one utmp record; skipped",
                Some(format!("size={} bytes", bytes.len())),
            ));
        }
        return;
    }
    if bytes.len() % WTMP_RECORD_SIZE != 0 {
        errors.push(super::collection_error(
            "login_records",
            path,
            "size_check",
            "file size not a multiple of 384; trailing partial record skipped",
            Some(format!("size={} bytes", bytes.len())),
        ));
    }
    let count = (bytes.len() / WTMP_RECORD_SIZE).min(MAX_RECORDS_PER_FILE);
    if bytes.len() / WTMP_RECORD_SIZE > MAX_RECORDS_PER_FILE {
        errors.push(super::collection_error(
            "login_records",
            path,
            "record_cap",
            "record count exceeded the per-file cap; remaining records skipped",
            Some(format!(
                "records={}, cap={MAX_RECORDS_PER_FILE}",
                bytes.len() / WTMP_RECORD_SIZE
            )),
        ));
    }
    for index in 0..count {
        let record = &bytes[index * WTMP_RECORD_SIZE..(index + 1) * WTMP_RECORD_SIZE];
        if let Some(row) = parse_utmp_record(record, source) {
            rows.push(row);
        }
    }
}

/// 先 metadata 预检再读取：文件缺失静默跳过；超上限只 `take` 前 cap 字节并登记
/// 截断错误；上限内全量读。绝不整读大文件（btmp 常见 GB 级）。
/// cap 参数化以便用小样本单测截断路径。
fn read_login_file_capped(
    path: &str,
    source: &str,
    cap: u64,
    errors: &mut Vec<CollectionError>,
) -> Option<Vec<u8>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            // 文件不存在是正常状态（部分系统没有 btmp/lastlog），静默跳过；
            // 只有存在但不可读（权限）才记录采集缺口。
            if error.kind() == std::io::ErrorKind::NotFound {
                return None;
            }
            errors.push(super::collection_error(
                source,
                path,
                "read_metadata",
                "login record file exists but could not be stat/read (permission)",
                Some(error.to_string()),
            ));
            return None;
        }
    };
    if !metadata.is_file() {
        return None;
    }
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            errors.push(super::collection_error(
                source,
                path,
                "open",
                "login record file exists but could not be read (permission)",
                Some(error.to_string()),
            ));
            return None;
        }
    };
    if metadata.len() <= cap {
        let mut bytes = Vec::new();
        match file.read_to_end(&mut bytes) {
            Ok(_) => Some(bytes),
            Err(error) => {
                errors.push(super::collection_error(
                    source,
                    path,
                    "read",
                    "login record file could not be read fully",
                    Some(error.to_string()),
                ));
                None
            }
        }
    } else {
        // 超上限：只读前 cap 字节（读取量有界），登记截断说明。
        let mut bytes = Vec::new();
        let mut limited = file.take(cap);
        match limited.read_to_end(&mut bytes) {
            Ok(_) => {
                errors.push(super::collection_error(
                    source,
                    path,
                    "size_cap",
                    "login record file exceeded the read cap; only the first cap bytes were retained (older records)",
                    Some(format!("size={} bytes, cap={cap} bytes", metadata.len())),
                ));
                Some(bytes)
            }
            Err(error) => {
                errors.push(super::collection_error(
                    source,
                    path,
                    "read",
                    "login record file could not be read within the cap",
                    Some(error.to_string()),
                ));
                None
            }
        }
    }
}

fn parse_utmp_record(record: &[u8], source: &str) -> Option<LoginRow> {
    let ut_type = u16::from_ne_bytes([record[0], record[1]]);
    if !matches!(
        ut_type,
        USER_PROCESS
            | DEAD_PROCESS
            | BOOT_TIME
            | SHUTDOWN_TIME
            | LOGIN_PROCESS
            | RUN_LVL
            | INIT_PROCESS
    ) {
        return None;
    }
    let pid = i32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
    let line = c_string(&record[8..40]);
    let user = c_string(&record[44..76]);
    let host = c_string(&record[76..332]);
    // ut_tv.tv_sec 按无符号读取再放大：i32 读法在 2038 后会变成负数时间戳。
    let tv_sec = u32::from_ne_bytes([record[340], record[341], record[342], record[343]]) as i64;
    let address = format_ut_addr_v6(&record[348..364]);
    let record_type = match ut_type {
        BOOT_TIME => "boot_time",
        LOGIN_PROCESS => "login_pending",
        USER_PROCESS => "user_process",
        DEAD_PROCESS => "logout",
        RUN_LVL => "runlevel",
        INIT_PROCESS => "init_process",
        SHUTDOWN_TIME => "shutdown",
        _ => return None,
    };
    Some(LoginRow {
        source: source.to_string(),
        record_type: record_type.to_string(),
        user,
        terminal: line,
        host,
        address,
        pid: pid.to_string(),
        timestamp: crate::time_utils::format_epoch_iso(tv_sec),
    })
}

/// 解析 utmp 16 字节 ut_addr_v6：
/// - 全 0 → 无地址（空串）；
/// - v4-mapped（::ffff:a.b.c.d，前 10 字节为 0 且第 10/11 字节为 0xff）→ 点分 IPv4；
/// - 其余且仅首 4 字节非 0 → 旧式 IPv4（网络序存于首字）；
/// - 否则输出完整 8 组冒号十六进制（无损保留 IPv6 溯源信息）。
fn format_ut_addr_v6(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), 16);
    if bytes.iter().all(|byte| *byte == 0) {
        return String::new();
    }
    let v4_mapped = bytes[0..10].iter().all(|byte| *byte == 0)
        && bytes[10] == 0xff
        && bytes[11] == 0xff;
    if v4_mapped {
        let word = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let octets = word.to_be_bytes();
        return format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
    }
    if bytes[4..].iter().all(|byte| *byte == 0) {
        let word = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let octets = word.to_be_bytes();
        return format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
    }
    (0..8)
        .map(|index| format!("{:02x}{:02x}", bytes[index * 2], bytes[index * 2 + 1]))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_lastlog(rows: &mut Vec<LoginRow>, errors: &mut Vec<CollectionError>) {
    const PATH: &str = "/var/log/lastlog";
    // lastlog 常按最大 UID 稀疏分配（可虚占数 GB）；同样 64MB take 上限。
    let Some(bytes) = read_login_file_capped(PATH, "login_records", MAX_WTMP_BYTES, errors)
    else {
        return;
    };
    // time_t 大小与平台指针宽度一致：64 位为 8 字节（记录 296），32 位为 4 字节（记录 292）。
    let time_size = if cfg!(target_pointer_width = "64") {
        8
    } else {
        4
    };
    let record_size = time_size + 32 + 256;
    let mut count = 0usize;
    for (uid, offset) in (0..).map(|uid| (uid, uid * record_size)) {
        if offset + record_size > bytes.len() || count >= MAX_RECORDS_PER_FILE {
            break;
        }
        let record = &bytes[offset..offset + record_size];
        let epoch = if time_size == 8 {
            i64::from_ne_bytes([
                record[0], record[1], record[2], record[3], record[4], record[5], record[6],
                record[7],
            ])
        } else {
            i64::from(i32::from_ne_bytes([
                record[0], record[1], record[2], record[3],
            ]))
        };
        if epoch <= 0 {
            continue;
        }
        let line = c_string(&record[time_size..time_size + 32]);
        let host = c_string(&record[time_size + 32..time_size + 32 + 256]);
        rows.push(LoginRow {
            source: "lastlog".to_string(),
            record_type: "last_login".to_string(),
            user: uid_name(uid),
            terminal: line,
            host,
            address: String::new(),
            pid: String::new(),
            timestamp: crate::time_utils::format_epoch_iso(epoch),
        });
        count += 1;
    }
}

fn uid_name(uid: usize) -> String {
    let Ok(content) = fs::read_to_string("/etc/passwd") else {
        return format!("uid:{uid}");
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[2].parse::<usize>().ok() == Some(uid) {
            return fields[0].to_string();
        }
    }
    format!("uid:{uid}")
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_record(ut_type: u16, user: &str, host: &str, line: &str, epoch: u32) -> Vec<u8> {
        let mut record = vec![0u8; WTMP_RECORD_SIZE];
        record[0..2].copy_from_slice(&ut_type.to_ne_bytes());
        record[4..8].copy_from_slice(&7i32.to_ne_bytes());
        record[8..8 + line.len()].copy_from_slice(line.as_bytes());
        record[44..44 + user.len()].copy_from_slice(user.as_bytes());
        record[76..76 + host.len()].copy_from_slice(host.as_bytes());
        record[340..344].copy_from_slice(&epoch.to_ne_bytes());
        // IPv4 10.0.0.5 → 网络序首字
        let addr = u32::from_be_bytes([10, 0, 0, 5]);
        record[348..352].copy_from_slice(&addr.to_ne_bytes());
        record
    }

    #[test]
    fn parses_user_process_record() {
        let record = build_record(USER_PROCESS, "root", "10.0.0.5", "pts/0", 1_700_000_000);
        let row = parse_utmp_record(&record, "wtmp").unwrap();
        assert_eq!(row.record_type, "user_process");
        assert_eq!(row.user, "root");
        assert_eq!(row.terminal, "pts/0");
        assert_eq!(row.address, "10.0.0.5");
        assert!(!row.timestamp.is_empty());
    }

    #[test]
    fn parses_boot_and_dead_records() {
        let boot = build_record(BOOT_TIME, "reboot", "0.0.0.0", "~", 1_700_000_100);
        assert_eq!(
            parse_utmp_record(&boot, "wtmp").unwrap().record_type,
            "boot_time"
        );
        let dead = build_record(DEAD_PROCESS, "", "", "pts/0", 1_700_000_200);
        assert_eq!(
            parse_utmp_record(&dead, "wtmp").unwrap().record_type,
            "logout"
        );
    }

    #[test]
    fn skips_unknown_record_types() {
        let record = build_record(9, "x", "", "", 0);
        assert!(parse_utmp_record(&record, "wtmp").is_none());
    }

    #[test]
    fn timestamps_survive_2038_when_read_as_u32() {
        // 3_000_000_000 > i32::MAX：u32 读取后仍应为正向 ISO 时间。
        let record = build_record(USER_PROCESS, "root", "", "pts/1", 3_000_000_000);
        let row = parse_utmp_record(&record, "wtmp").unwrap();
        assert!(row.timestamp.starts_with("2065"), "got {}", row.timestamp);
    }

    #[test]
    fn formats_v4_mapped_legacy_and_native_ipv6_addresses() {
        // 全 0 → 空。
        assert_eq!(format_ut_addr_v6(&[0u8; 16]), "");
        // 旧式 IPv4（仅首 4 字节非 0，网络序）→ 10.0.0.5。
        let mut legacy = [0u8; 16];
        legacy[0..4].copy_from_slice(&0x0A000005u32.to_ne_bytes());
        assert_eq!(format_ut_addr_v6(&legacy), "10.0.0.5");
        // v4-mapped ::ffff:192.168.1.7（前 10 字节 0 + ffff + 末 4 字节 IPv4）。
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].copy_from_slice(&0xC0A80107u32.to_ne_bytes());
        assert_eq!(format_ut_addr_v6(&mapped), "192.168.1.7");
        // 原生 IPv6 2001:db8::1 → 完整 8 组十六进制。
        let mut native = [0u8; 16];
        native[0] = 0x20;
        native[1] = 0x01;
        native[2] = 0x0d;
        native[3] = 0xb8;
        native[15] = 0x01;
        assert_eq!(format_ut_addr_v6(&native), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn oversize_login_file_is_truncated_by_take_cap() {
        // 用小 cap（2 条记录）验证 take 截断路径：4 条记录只读前 2 条并登记错误。
        let dir = std::env::temp_dir().join(format!(
            "dumpall-wtmp-cap-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("wtmp");
        let mut content = Vec::new();
        for epoch in [1_700_000_000u32, 1_700_000_100, 1_700_000_200, 1_700_000_300] {
            content.extend_from_slice(&build_record(
                USER_PROCESS,
                "root",
                "10.0.0.5",
                "pts/0",
                epoch,
            ));
        }
        fs::write(&path, &content).unwrap();
        let mut errors = Vec::new();
        let bytes = read_login_file_capped(
            path.to_str().unwrap(),
            "login_records",
            (WTMP_RECORD_SIZE * 2) as u64,
            &mut errors,
        )
        .unwrap();
        assert_eq!(bytes.len(), WTMP_RECORD_SIZE * 2);
        assert!(errors.iter().any(|error| error.operation == "size_cap"));
        // 实际 64MB cap 下同一文件应完整读取且无错误。
        let mut full_errors = Vec::new();
        let full = read_login_file_capped(
            path.to_str().unwrap(),
            "login_records",
            MAX_WTMP_BYTES,
            &mut full_errors,
        )
        .unwrap();
        assert_eq!(full.len(), content.len());
        assert!(full_errors.is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
