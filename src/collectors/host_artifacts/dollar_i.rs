//! 回收站 $I 元数据文件的纯字节解析（v1/v2）。
//!
//! 独立于平台 API（不触碰 windows_sys），可在任意平台做单元测试；
//! 文件枚举/盘符发现仍由 win_artifacts（cfg(windows)）负责。
//!
//! v2（Win10 及以后常见）：version(8) size(8) FILETIME(8) 路径长度(4，UTF-16
//! 单元数) + 变长 UTF-16 路径。
//! v1（Vista/2008）：固定 544 字节头 —— version@0(u64)、file_size@0x08(u64)、
//! 删除时间@0x10(FILETIME u64)、原始路径@0x14(20) 起固定 520 字节 UTF-16。
//! 不足 544 字节的 v1 文件视为损坏，不解析（长度守卫必须覆盖固定头全长,
//! 否则截断样本会造成字节切片越界）。

use std::fs;
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecycleRow {
    pub(crate) drive: String,
    pub(crate) sid: String,
    pub(crate) file_size: String,
    pub(crate) deleted_at: String,
    pub(crate) original_path: String,
}

// 文件封装入口仅在 Windows 采集路径调用;非 Windows 构建下测试只覆盖纯字节解析。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_dollar_i_file(path: &Path, drive: &str, sid: &str) -> Option<RecycleRow> {
    let bytes = fs::read(path).ok()?;
    parse_dollar_i_bytes(&bytes, drive, sid)
}

pub(crate) fn parse_dollar_i_bytes(bytes: &[u8], drive: &str, sid: &str) -> Option<RecycleRow> {
    if bytes.len() < 24 {
        return None;
    }
    let version = le_u64(bytes, 0);
    match version {
        2 => {
            if bytes.len() < 28 {
                return None;
            }
            let size = le_u64(bytes, 8);
            let deleted_at = filetime_to_iso(le_u64(bytes, 16));
            let path_len = le_u32(bytes, 24) as usize;
            let path_bytes = path_len.checked_mul(2)?;
            if path_bytes > 64 * 1024 || bytes.len() < 28 + path_bytes {
                return None;
            }
            let text: String = String::from_utf16_lossy(
                &bytes[28..28 + path_bytes]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<u16>>(),
            );
            Some(RecycleRow {
                drive: drive.to_string(),
                sid: sid.to_string(),
                file_size: size.to_string(),
                deleted_at,
                original_path: text.trim_end_matches('\0').to_string(),
            })
        }
        1 => {
            // 损坏/截断的 v1 文件（<544 字节）不解析，避免越界。
            if bytes.len() < 544 {
                return None;
            }
            let size = le_u64(bytes, 8);
            let deleted_at = filetime_to_iso(le_u64(bytes, 16));
            let name_bytes: Vec<u16> = bytes[20..544]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|unit| *unit != 0)
                .collect();
            Some(RecycleRow {
                drive: drive.to_string(),
                sid: sid.to_string(),
                file_size: size.to_string(),
                deleted_at,
                original_path: String::from_utf16_lossy(&name_bytes),
            })
        }
        _ => None,
    }
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// FILETIME（1601 起 100ns 单位）→ ISO8601。
fn filetime_to_iso(value: u64) -> String {
    if value == 0 {
        return String::new();
    }
    let unix_100ns = value.saturating_sub(116_444_736_000_000_000);
    let seconds = (unix_100ns / 10_000_000) as i64;
    crate::time_utils::format_epoch_iso(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_dollar_i_record() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes()); // version
        bytes.extend_from_slice(&1234u64.to_le_bytes()); // file size @8
        bytes.extend_from_slice(&132_244_336_000_000_000u64.to_le_bytes()); // FILETIME @16 (~2020)
        let text: Vec<u16> = "C:\\Users\\bob\\secret.exe".encode_utf16().collect();
        bytes.extend_from_slice(&(text.len() as u32).to_le_bytes()); // len @24
        for unit in text {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let row = parse_dollar_i_bytes(&bytes, "C:", "S-1-5-21").unwrap();
        assert_eq!(row.file_size, "1234");
        assert!(row.original_path.contains("secret.exe"));
        assert!(!row.deleted_at.is_empty());
    }

    #[test]
    fn parses_v1_dollar_i_fixed_header() {
        let mut bytes = vec![0u8; 544];
        bytes[0..8].copy_from_slice(&1u64.to_le_bytes()); // version @0
        bytes[8..16].copy_from_slice(&4096u64.to_le_bytes()); // file size @0x08
        bytes[16..24].copy_from_slice(&132_244_336_000_000_000u64.to_le_bytes()); // FILETIME @0x10
        let text: Vec<u16> = "C:\\Users\\alice\\报告.doc".encode_utf16().collect();
        for (index, unit) in text.iter().enumerate() {
            bytes[20 + index * 2..20 + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let row = parse_dollar_i_bytes(&bytes, "D:", "S-1-5-21-x").unwrap();
        assert_eq!(row.file_size, "4096");
        assert_eq!(row.original_path, "C:\\Users\\alice\\报告.doc");
        assert!(!row.deleted_at.is_empty());
    }

    #[test]
    fn rejects_v1_records_shorter_than_fixed_header() {
        // version=1 且 24 <= len < 544 的畸形样本：历史上会在 bytes[128..] 越界 panic。
        for length in [24usize, 100, 128, 543] {
            let mut bytes = vec![0u8; length];
            bytes[0..8].copy_from_slice(&1u64.to_le_bytes());
            assert!(
                parse_dollar_i_bytes(&bytes, "C:", "S-1").is_none(),
                "len={length} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_truncated_v2_dollar_i_record() {
        let bytes = vec![0u8; 24];
        assert!(parse_dollar_i_bytes(&bytes, "C:", "S-1").is_none());
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = vec![0u8; 544];
        bytes[0..8].copy_from_slice(&9u64.to_le_bytes());
        assert!(parse_dollar_i_bytes(&bytes, "C:", "S-1").is_none());
    }
}
