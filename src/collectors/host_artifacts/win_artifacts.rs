//! Windows P2 补充采集：注册表 hive 副本（reg save 到 raw/hives/）、
//! 回收站 $I 元数据解析、Recent/启动菜单 LNK 清单、BITS 任务、
//! PowerShell Alias、AppCompat 自定义 SDB、用户目录时间窗扫描。

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use crate::collectors::command::{collect_text_command, CommandSpec};

const RECYCLE_HEADER: &str = "drive,sid,file_size,deleted_at,original_path\n";
const RMT_TOOLS_HEADER: &str = "tool,path,size,mtime\n";

/// 银狐类远控后门常用工具的安装/配置位置（配置含无人值守凭据，溯源关键）。
const REMOTE_TOOL_DIRS: [(&str, &[&str]); 7] = [
    (
        "ToDesk",
        &[
            "C:\\Program Files\\ToDesk",
            "C:\\Program Files (x86)\\ToDesk",
            "C:\\ProgramData\\ToDesk",
        ],
    ),
    (
        "SunLogin",
        &[
            "C:\\Program Files\\Oray\\SunLogin",
            "C:\\Program Files (x86)\\Oray\\SunLogin",
            "C:\\ProgramData\\Oray",
        ],
    ),
    (
        "RustDesk",
        &["C:\\Program Files\\RustDesk", "C:\\ProgramData\\RustDesk"],
    ),
    (
        "AnyDesk",
        &[
            "C:\\Program Files\\AnyDesk",
            "C:\\ProgramData\\AnyDesk",
            "C:\\Users\\Public\\Documents\\AnyDesk",
        ],
    ),
    (
        "TeamViewer",
        &[
            "C:\\Program Files\\TeamViewer",
            "C:\\Program Files (x86)\\TeamViewer",
            "C:\\ProgramData\\TeamViewer",
        ],
    ),
    (
        "Radmin",
        &[
            "C:\\Program Files\\Radmin",
            "C:\\Windows\\System32\\rserver30",
        ],
    ),
    ("NetSupport", &["C:\\Program Files\\NetSupport"]),
];
const LNK_HEADER: &str = "path,size,mtime\n";
const SDB_HEADER: &str = "path,size,mtime\n";
const USER_DIRS_HEADER: &str = "path,dir,size,mtime\n";

#[derive(Debug, Clone, Serialize)]
struct InventoryRow {
    path: String,
    dir: String,
    size: String,
    mtime: String,
}

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    save_registry_hives(layout, errors)?;
    collect_remote_tools(layout)?;
    collect_recycle_bin(layout)?;
    collect_lnk_inventory(layout)?;
    collect_sdb_inventory(layout)?;
    collect_user_dirs(layout)?;
    // BITS 与 PowerShell Alias 走 PowerShell 只读查询。
    let bits = layout.collection_dir.join("bits_jobs.csv");
    collect_text_command(
        "bits_jobs",
        &bits,
        "display_name,owner_account,state,creation_time\n",
        &[bits_commands()],
        errors,
        false,
    )?;
    let aliases = layout.collection_dir.join("powershell_aliases.csv");
    collect_text_command(
        "powershell_aliases",
        &aliases,
        "name,definition,source\n",
        &[alias_commands()],
        errors,
        false,
    )
}

/// reg save 把在用 hive 导出为文件（对系统只读，输出到结果目录 raw/hives/）。
fn save_registry_hives(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    let hive_dir = layout.raw_dir.join("hives");
    fs::create_dir_all(&hive_dir)?;
    let reg = std::env::var_os("SystemRoot")
        .map(|root| Path::new(&root).join("System32").join("reg.exe"))
        .unwrap_or_else(|| Path::new(r"C:\Windows\System32\reg.exe").to_path_buf());
    let mut targets: Vec<(String, String)> = vec![
        ("HKLM\\SYSTEM".to_string(), "SYSTEM".to_string()),
        ("HKLM\\SOFTWARE".to_string(), "SOFTWARE".to_string()),
        ("HKLM\\SECURITY".to_string(), "SECURITY".to_string()),
        ("HKLM\\SAM".to_string(), "SAM".to_string()),
    ];
    // 用户 NTUSER.DAT：经 HKU hive 键名导出。
    if let Ok(output) = std::process::Command::new(&reg)
        .args(["query", "HKU"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim_end_matches('\r').trim();
                if trimmed.starts_with("HKEY_USERS\\S-") && !trimmed.ends_with("_Classes") {
                    let sid = trimmed.trim_start_matches("HKEY_USERS\\").to_string();
                    targets.push((format!("HKU\\{sid}"), format!("NTUSER_{sid}")));
                }
            }
        }
    }
    let mut saved = 0usize;
    for (key, name) in targets {
        let destination = hive_dir.join(name);
        let output = std::process::Command::new(&reg)
            .args(["save", &key])
            .arg(&destination)
            .arg("/y")
            .output();
        match output {
            Ok(result) if result.status.success() => saved += 1,
            Ok(result) => errors.push(super::collection_error(
                "registry_hives",
                key.clone(),
                "reg save",
                "hive could not be exported (privilege or in-use)",
                Some(String::from_utf8_lossy(&result.stderr).trim().to_string()),
            )),
            Err(error) => errors.push(super::collection_error(
                "registry_hives",
                key,
                "reg save",
                "reg.exe could not be executed",
                Some(error.to_string()),
            )),
        }
    }
    if saved == 0 {
        errors.push(super::collection_error(
            "registry_hives",
            "raw/hives",
            "reg save",
            "no registry hive could be exported (SYSTEM privilege typically required for SAM/SECURITY)",
            None,
        ));
    }
    Ok(())
}

/// 远控工具清点：目录存在即登记其文件（含 config.ini 等凭据文件），
/// 是银狐类"伪装远控投毒"场景的核心溯源证据。
fn collect_remote_tools(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    for (tool, dirs) in REMOTE_TOOL_DIRS {
        for dir in dirs {
            let root = Path::new(dir);
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                rows.push(InventoryRow {
                    path: path.display().to_string(),
                    dir: (*dir).to_string(),
                    size: if metadata.is_file() {
                        metadata.len().to_string()
                    } else {
                        String::new()
                    },
                    mtime: metadata
                        .modified()
                        .ok()
                        .map(crate::time_utils::system_time_to_iso)
                        .unwrap_or_default(),
                });
                let _ = tool;
            }
        }
    }
    let target = layout.collection_dir.join("remote_tools.csv");
    if rows.is_empty() {
        writers::write_text(&target, RMT_TOOLS_HEADER)
    } else {
        writers::write_csv_serialize(&target, &rows)
    }
}

/// 解析各盘符 $Recycle.Bin\<sid>\$I* 文件（v2: 24 字节头 + UTF-16 路径；v1: 544 字节固定头）。
/// 纯字节解析与单元测试见 super::dollar_i。
fn collect_recycle_bin(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    for drive in logical_drives() {
        let bin = Path::new(&drive).join("$Recycle.Bin");
        let Ok(sids) = fs::read_dir(&bin) else {
            continue;
        };
        for sid_entry in sids.flatten() {
            if !sid_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let sid = sid_entry.file_name().to_string_lossy().to_string();
            let Ok(files) = fs::read_dir(sid_entry.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let name = file.file_name().to_string_lossy().to_string();
                if !name.starts_with("$I") {
                    continue;
                }
                if let Some(row) =
                    super::dollar_i::parse_dollar_i_file(&path, &drive, &sid)
                {
                    rows.push(row);
                }
            }
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.recycle_bin, RECYCLE_HEADER)
    } else {
        writers::write_csv_serialize(&layout.recycle_bin, &rows)
    }
}

fn logical_drives() -> Vec<String> {
    let mask = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    (0..26)
        .filter(|bit| mask & (1u32 << bit) != 0)
        .map(|bit| format!("{}:", (b'A' + bit as u8) as char))
        .collect()
}

fn collect_lnk_inventory(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        roots.push(
            Path::new(&profile)
                .join("AppData")
                .join("Roaming")
                .join("Microsoft")
                .join("Windows")
                .join("Recent"),
        );
    }
    roots.push(
        Path::new("C:\\Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup"),
    );
    if let Ok(profile) = std::env::var("USERPROFILE") {
        roots.push(
            Path::new(&profile)
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }
    collect_files_inventory(&roots, "lnk", &mut rows);
    if rows.is_empty() {
        writers::write_text(&layout.lnk_inventory, LNK_HEADER)
    } else {
        writers::write_csv_serialize(&layout.lnk_inventory, &rows)
    }
}

fn collect_sdb_inventory(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    let roots = vec![Path::new("C:\\Windows").join("AppCompat").join("Programs")];
    collect_files_inventory(&roots, "sdb", &mut rows);
    if rows.is_empty() {
        writers::write_text(&layout.appcompat_sdb, SDB_HEADER)
    } else {
        writers::write_csv_serialize(&layout.appcompat_sdb, &rows)
    }
}

fn collect_user_dirs(layout: &OutputLayout) -> Result<()> {
    let mut rows = Vec::new();
    let mut roots: Vec<std::path::PathBuf> = vec![
        Path::new("C:\\Windows").join("Temp"),
        Path::new("C:\\Users").join("Public"),
    ];
    if let Ok(entries) = fs::read_dir("C:\\Users") {
        for entry in entries.flatten() {
            let user = entry.file_name().to_string_lossy().to_string();
            if [
                "All Users",
                "Default",
                "Public",
                "Default User",
                "desktop.ini",
            ]
            .contains(&user.as_str())
            {
                continue;
            }
            for sub in [
                "Desktop",
                "Downloads",
                "AppData\\Local\\Temp",
                // 每用户级事件查看器"自定义视图"查询定义。
                "AppData\\Local\\Microsoft\\Event Viewer\\Queries",
            ] {
                roots.push(entry.path().join(sub));
            }
        }
    }
    collect_files_inventory(&roots, "", &mut rows);
    if rows.is_empty() {
        writers::write_text(&layout.user_dirs, USER_DIRS_HEADER)
    } else {
        writers::write_csv_serialize(&layout.user_dirs, &rows)
    }
}

/// 极简清单收集：扩展名可空（空=全部），带上限。
fn collect_files_inventory(
    roots: &[std::path::PathBuf],
    extension: &str,
    rows: &mut Vec<InventoryRow>,
) {
    const MAX_ROWS: usize = 20_000;
    for root in roots {
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > 8 || rows.len() >= MAX_ROWS {
                break;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if rows.len() >= MAX_ROWS {
                    return;
                }
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    stack.push((path, depth + 1));
                    continue;
                }
                if !extension.is_empty()
                    && !path
                        .extension()
                        .map(|ext| ext.eq_ignore_ascii_case(extension))
                        .unwrap_or(false)
                {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                rows.push(InventoryRow {
                    path: path.display().to_string(),
                    dir: root.display().to_string(),
                    size: metadata.len().to_string(),
                    mtime: metadata
                        .modified()
                        .ok()
                        .map(crate::time_utils::system_time_to_iso)
                        .unwrap_or_default(),
                });
            }
        }
    }
}

fn bits_commands() -> CommandSpec {
    let script = r#"
Get-BitsTransfer -AllUsers |
  Select-Object @{Name='display_name';Expression={$_.DisplayName}},
    @{Name='owner_account';Expression={$_.OwnerAccount}},
    @{Name='state';Expression={$_.JobState}},
    @{Name='creation_time';Expression={$_.CreationTime}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn alias_commands() -> CommandSpec {
    let script = r#"
Get-Alias |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='definition';Expression={$_.Definition}},
    @{Name='source';Expression={$_.Source}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

