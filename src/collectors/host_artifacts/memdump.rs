//! Linux 原生物理内存获取（参数门控，root 权限）。
//!
//! 实现思路（与业界 Linux 内存采集器一致的纯用户态方案）：
//! 1. 解析 /proc/iomem 的 "System RAM" 区间（需要 CAP_SYS_ADMIN/root，否则显示全 0）。
//! 2. 首选 /proc/kcore：内核导出的 ELF64 core 伪文件，PT_LOAD 段由
//!    `first_vaddr - first_ram_start` 推出 vaddr→物理基址，段内偏移即文件偏移。
//! 3. 回退 /dev/crash（页对齐逐页读）与 /dev/mem（受 CONFIG_STRICT_DEVMEM 限制）。
//! 4. 输出 LiME v1 兼容格式（magic "EMiL"，32 字节头/块），分析机可直接用
//!    Volatility 等工具解析。
//!
//! 只读边界：仅打开内存源设备读取，不做 ptrace、不做内核模块加载。

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use crate::config::ResolvedRun;
use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;

use super::memory::MEMORY_DUMP_NAME;

/// LiME 头魔数 "EMiL"（小端 u32）。
const LIME_MAGIC: u32 = 0x454d_694c;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone)]
struct Block {
    /// 源文件内的读取偏移。
    offset: u64,
    /// 物理地址区间（含头）。
    range: Range<u64>,
}

/// 原生内存获取入口：按 kcore → /dev/crash → /dev/mem 顺序尝试。
pub fn acquire_native(_resolved: &ResolvedRun, layout: &OutputLayout) -> Result<String> {
    let ranges = parse_iomem()?;
    if ranges.is_empty() {
        return Err(DumpallError::invalid_argument(
            "memory-dump",
            "no System RAM ranges parsed from /proc/iomem (root/CAP_SYS_ADMIN required)",
        ));
    }
    std::fs::create_dir_all(&layout.raw_dir)?;
    let destination = layout.raw_dir.join(MEMORY_DUMP_NAME);
    let total: u64 = ranges.iter().map(|r| r.end - r.start).sum();

    // 写盘前空间预检：物理内存映像约等于 RAM 总量，磁盘不足直接失败，
    // 避免写满磁盘影响业务（这是内存采集最大的系统风险点）。
    match available_bytes(&layout.raw_dir) {
        Some(free) if free < total => {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                format!(
                    "insufficient disk space: RAM ranges total {total} bytes but only {free} bytes free at {}",
                    layout.raw_dir.display()
                ),
            ));
        }
        Some(_) => {}
        None => {} // df 不可用时跳过预检，写入失败仍会中止
    }

    let attempts = [
        (
            "kcore",
            acquire_kcore as fn(&[Range<u64>], &Path) -> Result<()>,
        ),
        (
            "devcrash",
            acquire_dev_crash as fn(&[Range<u64>], &Path) -> Result<()>,
        ),
        (
            "devmem",
            acquire_dev_mem as fn(&[Range<u64>], &Path) -> Result<()>,
        ),
    ];
    let mut errors = Vec::new();
    for (name, acquire) in attempts {
        match acquire(&ranges, &destination) {
            Ok(()) => {
                let size = std::fs::metadata(&destination)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let hash = super::memory::sha256_file(&destination).unwrap_or_default();
                return Ok(format!(
                    "native memory acquisition via {name}: RAM ranges cover {total} bytes, wrote raw/{MEMORY_DUMP_NAME} ({size} bytes), sha256={hash}"
                ));
            }
            Err(error) => errors.push(format!("{name}: {error}")),
        }
        // 失败重试前清掉半成品。
        let _ = std::fs::remove_file(&destination);
    }
    Err(DumpallError::invalid_argument(
        "memory-dump",
        format!("all native memory sources failed: {}", errors.join("; ")),
    ))
}

/// 解析 /proc/iomem 顶层 "System RAM" 区间并合并相邻段。
pub(crate) fn parse_iomem() -> Result<Vec<Range<u64>>> {
    parse_iomem_file(Path::new("/proc/iomem"))
}

fn parse_iomem_file(path: &Path) -> Result<Vec<Range<u64>>> {
    let buffer = std::fs::read_to_string(path).map_err(|error| {
        DumpallError::invalid_argument("memory-dump", format!("read iomem failed: {error}"))
    })?;
    let mut ranges = Vec::new();
    for line in buffer.lines() {
        if line.starts_with(' ') {
            continue;
        }
        if !line.ends_with(" : System RAM") {
            continue;
        }
        let Some((span, _)) = line.split_once(':') else {
            continue;
        };
        let Some((start, end)) = span.trim().split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end, 16) else {
            continue;
        };
        if start == 0 && end == 0 {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                "iomem shows zeroed addresses: /proc/iomem requires root or CAP_SYS_ADMIN (kernel kptr_restrict)",
            ));
        }
        ranges.push(start..end + 1);
    }
    Ok(merge_ranges(ranges))
}

fn merge_ranges(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::new();
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// ELF64 程序头（本机字节序，仅取需要的字段）。
struct ProgramHeader {
    p_type: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_memsz: u64,
}

const PT_LOAD: u32 = 1;

fn parse_kcore_headers(file: &mut File) -> Result<Vec<ProgramHeader>> {
    let mut ehdr = [0u8; 64];
    file.read_exact(&mut ehdr).map_err(|error| {
        DumpallError::invalid_argument("memory-dump", format!("read kcore ELF header: {error}"))
    })?;
    if &ehdr[0..4] != b"\x7fELF" {
        return Err(DumpallError::invalid_argument(
            "memory-dump",
            "/proc/kcore is not an ELF file",
        ));
    }
    let class = ehdr[4];
    if class != 2 {
        return Err(DumpallError::invalid_argument(
            "memory-dump",
            "/proc/kcore is not ELF64",
        ));
    }
    let phoff = le_u64(&ehdr, 32);
    let phentsize = le_u16(&ehdr, 54) as usize;
    let phnum = le_u16(&ehdr, 56) as usize;
    if phentsize < 56 || phnum == 0 || phnum > 4096 {
        return Err(DumpallError::invalid_argument(
            "memory-dump",
            "/proc/kcore has unexpected program header layout",
        ));
    }
    let mut headers = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let mut ph = [0u8; 56];
        file.seek(SeekFrom::Start(phoff + (index * phentsize) as u64))
            .and_then(|_| file.read_exact(&mut ph))
            .map_err(|error| {
                DumpallError::invalid_argument("memory-dump", format!("read phdr: {error}"))
            })?;
        headers.push(ProgramHeader {
            p_type: le_u32(&ph, 0),
            p_offset: le_u64(&ph, 8),
            p_vaddr: le_u64(&ph, 16),
            p_memsz: le_u64(&ph, 40),
        });
    }
    Ok(headers
        .into_iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .collect())
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
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

/// 由 iomem RAM 区间与 kcore PT_LOAD 段求交集块（块内物理→文件偏移映射）。
fn find_kcore_blocks(ranges: &[Range<u64>], segments: &[ProgramHeader]) -> Vec<Block> {
    // vaddr 基址 = 首段 vaddr - 首个 RAM 区间起点。
    let (Some(first_segment), Some(first_range)) = (segments.first(), ranges.first()) else {
        return Vec::new();
    };
    let base = first_segment.p_vaddr.saturating_sub(first_range.start);
    let physical: Vec<(Range<u64>, u64)> = segments
        .iter()
        .map(|segment| {
            let start = segment.p_vaddr.saturating_sub(base);
            (
                start..start.saturating_add(segment.p_memsz),
                segment.p_offset,
            )
        })
        .collect();

    let mut blocks = Vec::new();
    'outer: for range in ranges {
        let mut start = range.start;
        while start < range.end {
            for (segment_range, offset) in &physical {
                if segment_range.contains(&start) {
                    let end = range.end.min(segment_range.end);
                    blocks.push(Block {
                        offset: offset + start - segment_range.start,
                        range: start..end,
                    });
                    if end >= range.end {
                        continue 'outer;
                    }
                    start = end;
                }
            }
            // 无覆盖段：跳过一个页继续，避免死循环。
            start = (start + PAGE_SIZE) & !(PAGE_SIZE - 1);
        }
    }
    blocks
}

fn acquire_kcore(ranges: &[Range<u64>], destination: &Path) -> Result<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .open("/proc/kcore")
        .map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("open kcore: {error}"))
        })?;
    let segments = parse_kcore_headers(&mut source)?;
    let blocks = find_kcore_blocks(ranges, &segments);
    if blocks.is_empty() {
        return Err(DumpallError::invalid_argument(
            "memory-dump",
            "no kcore PT_LOAD segments overlap System RAM (LOCKDOWN_KCORE?)",
        ));
    }
    write_lime(&mut source, destination, &blocks, false)
}

fn acquire_dev_crash(ranges: &[Range<u64>], destination: &Path) -> Result<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .open("/dev/crash")
        .map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("open /dev/crash: {error}"))
        })?;
    // /dev/crash 需页对齐且逐页读。
    let blocks: Vec<Block> = ranges
        .iter()
        .map(|range| Block {
            offset: range.start,
            range: range.start..(range.end & !(PAGE_SIZE - 1)),
        })
        .collect();
    write_lime(&mut source, destination, &blocks, true)
}

fn acquire_dev_mem(ranges: &[Range<u64>], destination: &Path) -> Result<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .open("/dev/mem")
        .map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("open /dev/mem: {error}"))
        })?;
    let blocks: Vec<Block> = ranges
        .iter()
        .map(|range| Block {
            offset: range.start,
            range: range.clone(),
        })
        .collect();
    write_lime(&mut source, destination, &blocks, true)
}

/// 写 LiME v1 格式：每块 32 字节头（magic/version/start/end-1/padding0）+ 原始数据。
fn write_lime(
    source: &mut File,
    destination: &Path,
    blocks: &[Block],
    page_aligned: bool,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut output = options.mode_0600().open(destination).map_err(|error| {
        DumpallError::invalid_argument("memory-dump", format!("create dump file: {error}"))
    })?;
    for block in blocks {
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&LIME_MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&1u32.to_le_bytes());
        header[8..16].copy_from_slice(&block.range.start.to_le_bytes());
        header[16..24].copy_from_slice(&(block.range.end - 1).to_le_bytes());
        output.write_all(&header).map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("write header: {error}"))
        })?;
        source
            .seek(SeekFrom::Start(block.offset))
            .map_err(|error| {
                DumpallError::invalid_argument("memory-dump", format!("seek source: {error}"))
            })?;
        copy_pages(
            source,
            &mut output,
            block.range.end - block.range.start,
            page_aligned,
        )?;
    }
    output.flush().map_err(|error| {
        DumpallError::invalid_argument("memory-dump", format!("flush dump: {error}"))
    })
}

fn copy_pages(
    source: &mut File,
    output: &mut File,
    mut remaining: u64,
    page_aligned: bool,
) -> Result<()> {
    let chunk = if page_aligned {
        PAGE_SIZE as usize
    } else {
        1024 * 1024
    };
    let mut buffer = vec![0u8; chunk];
    while remaining > 0 {
        let want = buffer.len().min(remaining as usize);
        source.read_exact(&mut buffer[..want]).map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("read page: {error}"))
        })?;
        output.write_all(&buffer[..want]).map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("write page: {error}"))
        })?;
        remaining -= want as u64;
    }
    Ok(())
}

/// 目标目录可用空间（字节）：优先 GNU df -B1，回退 df -k×1024。
fn available_bytes(directory: &Path) -> Option<u64> {
    let df = super::which("df")?;
    for (args, unit) in [(vec!["-B1", "-P"], 1u64), (vec!["-k", "-P"], 1024u64)] {
        let output = std::process::Command::new(&df)
            .args(&args)
            .arg(directory)
            .output()
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text.lines().nth(1)?;
        // -P 保证单行；可用空间是第 4 列。
        let available = line.split_whitespace().nth(3)?.parse::<u64>().ok()?;
        return Some(available.saturating_mul(unit));
    }
    None
}

trait Mode0600 {
    fn mode_0600(self) -> Self;
}

#[cfg(unix)]
impl Mode0600 for OpenOptions {
    fn mode_0600(mut self) -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600);
        self
    }
}

#[cfg(not(unix))]
impl Mode0600 for OpenOptions {
    fn mode_0600(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_adjacent_ranges() {
        let merged = merge_ranges(vec![0..3, 3..6, 7..10]);
        assert_eq!(merged, vec![0..6, 7..10]);
    }

    #[test]
    fn parses_iomem_sample() {
        let dir = std::env::temp_dir().join(format!("dumpall-iomem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("iomem");
        std::fs::write(
            &path,
            "00000000-00000fff : reserved\n00001000-0009fbff : System RAM\n  00001000-000xxxxx : Kernel code\n100000000-13fffffffff : System RAM\n",
        )
        .unwrap();
        let ranges = parse_iomem_file(&path).unwrap();
        assert_eq!(ranges, vec![0x1000..0x9fc00, 0x100000000..0x14000000000]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kcore_blocks_intersect_segments() {
        #[allow(clippy::single_range_in_vec_init)]
        let ranges = vec![0x1000..0x8000];
        // 段 vaddr 基址 0xffff888000000000；RAM 区间起点 0x1000 推出 base 偏移。
        let segments = vec![ProgramHeader {
            p_type: PT_LOAD,
            p_offset: 0x1000,
            p_vaddr: 0xffff_8880_0000_0000,
            p_memsz: 0x10_0000,
        }];
        let blocks = find_kcore_blocks(&ranges, &segments);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].offset, 0x1000);
        assert_eq!(blocks[0].range, 0x1000..0x8000);
    }
}
