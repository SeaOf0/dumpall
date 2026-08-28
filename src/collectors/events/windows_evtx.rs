use std::fs;
use std::path::{Path, PathBuf};

use super::EventWindow;
use crate::collectors::collection_error;
use crate::config::ResolvedRun;
use crate::model::{CollectionError, ParseError, WindowsEvent};
use crate::parsers::access_log::sha256_hex;

pub const COLLECTOR_SCOPE: &str = "windows_evtx";
/// 文本/XML/JSON 事件导出需要交给现有解析器的 `&str`，因此设置独立内存上限；
/// 原生二进制 EVTX 走逐记录路径，不受此上限影响。
const MAX_TEXT_EVENT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct WindowsEventCollection {
    pub events: Vec<WindowsEvent>,
    pub parse_errors: Vec<ParseError>,
    pub errors: Vec<CollectionError>,
    pub files_scanned: u64,
    pub lines_seen: u64,
    /// 读取阶段被时间窗口剔除的事件条数（不消耗 max_event_records 配额）。
    pub window_filtered: u64,
}

pub fn collect_windows_events(resolved: &ResolvedRun) -> WindowsEventCollection {
    let mut report = WindowsEventCollection::default();
    for input in &resolved.evtx_paths {
        collect_input(input, resolved, &mut report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
    report
}

fn collect_input(path: &Path, resolved: &ResolvedRun, report: &mut WindowsEventCollection) {
    if !path.exists() {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "discover",
            "EVTX path does not exist",
            Some(
                "Verify the offline EVTX export path or rerun with a readable file/directory."
                    .to_string(),
            ),
        ));
        return;
    }
    if path.is_file() {
        parse_file(path, resolved, report);
        return;
    }
    if !path.is_dir() {
        return;
    }
    for file in event_files(path, resolved.safety.max_depth) {
        parse_file(&file, resolved, report);
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
}

fn parse_file(path: &Path, resolved: &ResolvedRun, report: &mut WindowsEventCollection) {
    // .evtx 通道单文件上限按 2048MB 下限执行：Security/System 等关键通道在
    // 实机上常超默认 512MB，被上限跳过会静默丢失登录爆破等核心证据；
    // 二进制解析为流式（evtx crate 分块读取），内存有界，不因上限放宽而膨胀。
    let is_evtx_path = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("evtx"));
    let cap_mb = if is_evtx_path {
        resolved.safety.max_file_size_mb.max(2048)
    } else {
        resolved.safety.max_file_size_mb
    };
    let max_bytes = cap_mb.saturating_mul(1024 * 1024);
    let Ok(metadata) = fs::metadata(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "metadata",
            "could not read EVTX export metadata",
            None,
        ));
        return;
    };
    if metadata.len() > max_bytes {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "preflight",
            format!(
                "event file exceeds max-file-size limit: {} bytes",
                metadata.len()
            ),
            None,
        ));
        return;
    }

    // 只嗅探文件头判定二进制 EVTX，避免把 GB 级通道整读进内存；
    // 文本导出仍按上限整读解析。
    let mut header = [0u8; 8];
    let binary = match fs::File::open(path) {
        Ok(mut file) => std::io::Read::read(&mut file, &mut header)
            .map(|_| is_evtx_path || header.starts_with(b"ElfFile"))
            .unwrap_or(is_evtx_path),
        Err(_) => is_evtx_path,
    };
    if binary {
        #[cfg(feature = "binary-evtx")]
        {
            handle_binary_evtx(path, resolved, report);
            return;
        }
        #[cfg(not(feature = "binary-evtx"))]
        {
            report.errors.push(collection_error(
                COLLECTOR_SCOPE,
                path.display().to_string(),
                "parse",
                "binary EVTX parsing is not enabled in this build; provide XML/JSON/JSONL export or rebuild with --features binary-evtx",
                Some("This build keeps EVTX collection offline and dependency-light; export the channel with XML or JSON records for parsing.".to_string()),
            ));
            return;
        }
    }
    if metadata.len() > MAX_TEXT_EVENT_BYTES {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "preflight",
            format!(
                "text event export exceeds in-memory parser limit: {} bytes (limit {})",
                metadata.len(),
                MAX_TEXT_EVENT_BYTES
            ),
            Some(
                "Use binary-evtx streaming or split the XML/JSON export into bounded files."
                    .to_string(),
            ),
        ));
        return;
    }
    let Ok(bytes) = fs::read(path) else {
        report.errors.push(collection_error(
            COLLECTOR_SCOPE,
            path.display().to_string(),
            "read",
            "could not read EVTX export file",
            None,
        ));
        return;
    };
    let text = match decode_text_export(&bytes) {
        Some(text) => text,
        None => {
            report.errors.push(collection_error(
                COLLECTOR_SCOPE,
                path.display().to_string(),
                "parse",
                "EVTX export was not decodable text (no UTF-8/UTF-16 BOM and neither UTF-8 nor UTF-16LE heuristics matched)",
                Some(
                    "Provide XML/JSON/JSONL export; PowerShell 5.1 Out-File UTF-16 exports are auto-detected via BOM."
                        .to_string(),
                ),
            ));
            return;
        }
    };
    report.files_scanned += 1;
    let (mut events, errors, lines_seen) = crate::parsers::evtx::parse_windows_export(path, &text);
    report.lines_seen += lines_seen;
    for event in &mut events {
        if resolved.safety.redact {
            redact_windows_event(event);
        }
    }
    for (line_number, message, raw_sample) in errors {
        report.parse_errors.push(ParseError {
            source_file: path.display().to_string(),
            line_number,
            parser_name: "windows_evtx_export".to_string(),
            message,
            raw_hash: sha256_hex(raw_sample.as_bytes()),
            raw_sample: Some(if resolved.safety.redact {
                crate::safety::redact_text(&raw_sample)
            } else {
                raw_sample
            }),
        });
    }
    retain_in_window_with_limit(events, resolved, report);
}

/// 边读边过滤后的统一入口：窗口外事件不计入 max_event_records 消耗，
/// 窗口内事件在配额内保留。保留最后兜底语义（apply_event_window 仍会再跑一遍）。
fn retain_in_window_with_limit(
    events: Vec<WindowsEvent>,
    resolved: &ResolvedRun,
    report: &mut WindowsEventCollection,
) {
    let window = EventWindow::from_resolved(resolved);
    for event in events {
        if !window.contains(event.timestamp.as_deref()) {
            report.window_filtered += 1;
            continue;
        }
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
        report.events.push(event);
    }
}

/// 文本事件导出解码：PowerShell 5.1 `Out-File`/`Get-Content | Out-File` 默认产出
/// UTF-16LE（带 FF FE BOM），旧导出可能是 UTF-16BE（FE FF）或带 BOM 的 UTF-8。
/// 解码顺序：BOM 优先（UTF-8 BOM 剥离 / UTF-16LE/BE 按 u16 解码），
/// 无 BOM 时先按 UTF-8 严格验证，失败后再做 UTF-16LE 启发
/// （偶数长度且奇数位字节大量为 NUL，即 ASCII 文本的 UTF-16 高位零字节），
/// 仍不匹配则返回 None 让调用方登记错误。
fn decode_text_export(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some(String::from_utf8_lossy(&bytes[3..]).into_owned());
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return Some(decode_utf16(&bytes[2..], true));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Some(decode_utf16(&bytes[2..], false));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Some(text.to_string());
    }
    if looks_like_utf16le(bytes) {
        return Some(decode_utf16(bytes, true));
    }
    None
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// UTF-16LE 无 BOM 启发：长度为偶数，且奇数位（ASCII 字符的高位字节）零占比过半。
fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return false;
    }
    let high_bytes = bytes.len() / 2;
    let zeros = bytes[1..]
        .chunks_exact(2)
        .filter(|pair| pair[0] == 0)
        .count();
    zeros * 2 > high_bytes
}

fn event_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, 0, max_depth, &mut files);
    // 核心通道优先：--max-event-records 总量有限时，先保证 Security/System
    // （登录/进程/服务证据）被解析，再消费诊断类通道；组内保持稳定顺序。
    files.sort_by_key(|path| {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.starts_with("security") {
            0
        } else if name.starts_with("system") {
            1
        } else if name.starts_with("windows powershell")
            || name.starts_with("microsoft-windows-powershell")
        {
            2
        } else {
            3
        }
    });
    files
}

fn walk(path: &Path, depth: usize, max_depth: usize, files: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&child, depth + 1, max_depth, files);
        } else if file_type.is_file() && is_probable_windows_event_file(&child) {
            files.push(child);
        }
    }
}

fn is_probable_windows_event_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".evtx")
        || name.ends_with(".xml")
        || name.ends_with(".json")
        || name.ends_with(".jsonl")
        || name.contains("security")
        || name.contains("powershell")
        || name.contains("taskscheduler")
        || name.contains("sysmon")
}

fn redact_windows_event(event: &mut WindowsEvent) {
    for field in [
        &mut event.user,
        &mut event.command_line_summary,
        &mut event.target_user,
        &mut event.object_path,
    ]
    .into_iter()
    .flatten()
    {
        *field = crate::safety::redact_text(field);
    }
}

/// 原生解析二进制 EVTX（feature binary-evtx）：逐记录导出 XML 字符串，
/// 复用现有 XML 导出解析路径，保持离线与只读。
#[cfg(feature = "binary-evtx")]
fn handle_binary_evtx(path: &Path, resolved: &ResolvedRun, report: &mut WindowsEventCollection) {
    use evtx::{EvtxParser, ParserSettings};
    let settings = ParserSettings::default().num_threads(resolved.safety.threads.max(1));
    let mut parser = match EvtxParser::from_path(path) {
        Ok(parser) => parser.with_configuration(settings),
        Err(error) => {
            report.errors.push(collection_error(
                COLLECTOR_SCOPE,
                path.display().to_string(),
                "parse",
                "binary EVTX file could not be opened",
                Some(error.to_string()),
            ));
            return;
        }
    };
    let mut record_count = 0u64;
    let mut parse_failures = 0u64;
    for record in parser.records() {
        match record {
            Ok(record) => {
                record_count += 1;
                // 逐记录解析，避免把整个 Security.evtx 拼成一个超大字符串。
                let (mut events, errors, _) =
                    crate::parsers::evtx::parse_windows_export(path, &record.data);
                if resolved.safety.redact {
                    for event in &mut events {
                        redact_windows_event(event);
                    }
                }
                // 窗口外记录不消耗 max_event_records 配额（二进制记录按旧→新顺序输出，
                // 若按原始记录数停读，事发时段的最新记录将永远读不到）。
                retain_in_window_with_limit(events, resolved, report);
                for (line_number, message, raw_sample) in errors {
                    report.parse_errors.push(ParseError {
                        source_file: path.display().to_string(),
                        line_number,
                        parser_name: "windows_evtx_binary".to_string(),
                        message,
                        raw_hash: sha256_hex(raw_sample.as_bytes()),
                        raw_sample: Some(if resolved.safety.redact {
                            crate::safety::redact_text(&raw_sample)
                        } else {
                            raw_sample
                        }),
                    });
                }
            }
            Err(_error) => {
                parse_failures += 1;
            }
        }
        if report.events.len() as u64 >= resolved.max_event_records {
            break;
        }
    }
    if parse_failures > 0 {
        report.parse_errors.push(ParseError {
            source_file: path.display().to_string(),
            line_number: 0,
            parser_name: "windows_evtx_binary".to_string(),
            message: format!("{parse_failures} binary record(s) could not be parsed"),
            raw_hash: String::new(),
            raw_sample: None,
        });
    }
    report.files_scanned += 1;
    report.lines_seen += record_count;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str =
        r#"<Events><Event><System><EventID>4688</EventID></System></Event></Events>"#;

    #[test]
    fn decodes_powershell_outfile_utf16le_with_bom() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in SAMPLE_XML.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_text_export(&bytes).expect("UTF-16LE BOM must decode");
        assert_eq!(decoded, SAMPLE_XML);
    }

    #[test]
    fn decodes_utf16be_with_bom() {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in SAMPLE_XML.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        let decoded = decode_text_export(&bytes).expect("UTF-16BE BOM must decode");
        assert_eq!(decoded, SAMPLE_XML);
    }

    #[test]
    fn decodes_utf16le_and_utf16be_symmetrically() {
        let text = "BadSvc C:\\Windows\\Temp\\bad.exe";
        let mut le = vec![0xFF, 0xFE];
        let mut be = vec![0xFE, 0xFF];
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
            be.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(decode_text_export(&le).as_deref(), Some(text));
        assert_eq!(decode_text_export(&be).as_deref(), Some(text));
    }

    #[test]
    fn strips_utf8_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(SAMPLE_XML.as_bytes());
        let decoded = decode_text_export(&bytes).expect("UTF-8 BOM must decode");
        assert_eq!(decoded, SAMPLE_XML);
    }

    #[test]
    fn keeps_plain_utf8_without_bom() {
        assert_eq!(
            decode_text_export(SAMPLE_XML.as_bytes()).as_deref(),
            Some(SAMPLE_XML)
        );
    }

    #[test]
    fn heuristic_detects_utf16le_without_bom() {
        // 非 ASCII 内容保证整体不是合法 UTF-8；ASCII 高位零字节过半触发启发。
        let text = "Event事件";
        let bytes: Vec<u8> = text
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert!(std::str::from_utf8(&bytes).is_err());
        let decoded = decode_text_export(&bytes).expect("UTF-16LE heuristic must decode");
        assert_eq!(decoded, text);
    }

    #[test]
    fn rejects_undecodable_bytes() {
        // 非偶数长度 / 零字节占比不足 → 无法判定编码。
        assert!(decode_text_export(&[0xC3, 0x28]).is_none());
        assert!(decode_text_export(&[0xFF, 0x00, 0xFE, 0x01]).is_none());
    }
}
