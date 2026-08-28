//! 内核模块清单采集：/proc/modules 原生解析，并与 /sys/module 目录对比。

use std::fs;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::push_collection_error;

const HEADER: &str = "name,size,ref_count,used_by,state,in_sysfs\n";

#[derive(Debug, Clone, Serialize)]
struct KernelModuleRow {
    name: String,
    size: String,
    ref_count: String,
    used_by: String,
    state: String,
    in_sysfs: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let mut rows = Vec::new();
    let content = match fs::read_to_string("/proc/modules") {
        Ok(content) => content,
        Err(error) => {
            push_collection_error(
                errors,
                "kernel_modules",
                "/proc/modules",
                "read_modules",
                "kernel module list could not be read",
                Some(error.to_string()),
            );
            writers::write_text(&layout.kernel_modules, HEADER)?;
            return Ok(());
        }
    };
    let sysfs_names = sysfs_module_names();
    for line in content.lines() {
        if let Some(row) = parse_module_line(line, &sysfs_names) {
            rows.push(row);
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.kernel_modules, HEADER)
    } else {
        writers::write_csv_serialize(&layout.kernel_modules, &rows)
    }
}

/// /proc/modules 行：`name size refcount used-by... [state] [address]`。
/// 状态列（Live/Loading/Unloading）通常是倒数第二列（最后列是模块地址，
/// 仅 kallsyms 打开的内核才输出）；带 kallsyms 的内核行如
/// `xfs 1634304 1 - Live 0xffffffffc057d000-...`。这里按状态关键字定位，
/// 兼容有/无地址列两种形态；找不到状态关键字时退化为最后一列。
fn parse_module_line(line: &str, sysfs_names: &[String]) -> Option<KernelModuleRow> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    let name = fields[0].to_string();
    let ref_count = fields[2].to_string();
    let used_by = if fields[3] == "-" || fields[3].is_empty() {
        String::new()
    } else {
        fields[3].to_string()
    };
    let state = fields
        .iter()
        .rev()
        .find(|field| matches!(**field, "Live" | "Loading" | "Unloading"))
        .map(|field| field.to_string())
        .unwrap_or_else(|| fields[fields.len() - 1].to_string());
    let in_sysfs = sysfs_names.contains(&name).to_string();
    Some(KernelModuleRow {
        name,
        size: fields[1].to_string(),
        ref_count,
        used_by,
        state,
        in_sysfs,
    })
}

fn sysfs_module_names() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/module") else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_row_field_layout_is_stable() {
        // /proc/modules 行格式：name size used-by refcount [deps] state
        assert_eq!(HEADER.lines().next().unwrap().split(',').count(), 6);
    }

    #[test]
    fn module_state_takes_live_not_address() {
        // 带 kallsyms 地址列（状态在倒数第二列，地址在最后列）。
        let line = "xfs 1634304 1 - Live 0xffffffffc057d000-0xffffffffc0580000";
        let row = parse_module_line(line, &[]).unwrap();
        assert_eq!(row.state, "Live");
        assert_eq!(row.name, "xfs");
        assert_eq!(row.used_by, "");
    }

    #[test]
    fn module_state_takes_loading_without_address() {
        // 无地址列（状态即最后一列）。
        let row = parse_module_line("evil_mod 40960 0 - Loading", &[]).unwrap();
        assert_eq!(row.state, "Loading");
        // 带 used-by 的行。
        let row = parse_module_line("nf_nat 32768 3 nf_conntrack,xt_nat 1 Live", &[]).unwrap();
        assert_eq!(row.state, "Live");
        assert_eq!(row.used_by, "nf_conntrack,xt_nat");
    }

    #[test]
    fn module_row_rejects_short_lines() {
        assert!(parse_module_line("only two fields", &[]).is_none());
    }
}
