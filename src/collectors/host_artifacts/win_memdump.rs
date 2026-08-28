//! Windows 原生进程内存转储（参数门控，管理员权限）。
//!
//! 实现思路（与 Sysinternals Procdump 等一致的用户态方案）：
//! 1. 提权 SeDebugPrivilege（AdjustTokenPrivileges，只改当前进程令牌）。
//! 2. Toolhelp32 快照枚举进程。
//! 3. 逐进程 OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ) 后调用
//!    系统自带 dbghelp!MiniDumpWriteDump(MiniDumpWithFullMemory) 生成标准
//!    .dmp（Windbg/Volatility 等可直接解析）。
//!
//! 说明：Windows 物理内存全量获取需要签名内核驱动，无法以单二进制只读方式完成；
//! 本实现覆盖所有进程的完整进程内存（含注入代码/ webshell 驻留），受保护进程
//! 会记录为跳过项。LSASS 等敏感进程转储默认包含并在清单中显式标记。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithCodeSegs, MiniDumpWithDataSegs, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
    MiniDumpWithPrivateReadWriteMemory, MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules,
    MiniDumpWriteDump,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// 转储前空间安全余量系数：目标盘剩余空间至少是估算转储量 的 1.5 倍。
const SPACE_HEADROOM_NUM: u64 = 3;
const SPACE_HEADROOM_DEN: u64 = 2;
/// 转储后磁盘剩余低于该值（1GB）即终止后续进程转储（防止写满盘拖垮业务机）。
const POST_DUMP_FREE_FLOOR: u64 = 1024 * 1024 * 1024;
/// 查不到进程内存信息时的静态下限（2GB）。
const STATIC_FREE_FLOOR: u64 = 2 * 1024 * 1024 * 1024;

/// 敏感进程名单：转储默认包含，但清单显式标记供复核。
const SENSITIVE_PROCESSES: [&str; 4] = ["lsass.exe", "winlogon.exe", "services.exe", "csrss.exe"];
const TRIAGE_PROCESSES: [&str; 16] = [
    "w3wp.exe",
    "iisexpress.exe",
    "php-cgi.exe",
    "php.exe",
    "java.exe",
    "javaw.exe",
    "node.exe",
    "python.exe",
    "pythonw.exe",
    "nginx.exe",
    "httpd.exe",
    "tomcat.exe",
    "powershell.exe",
    "pwsh.exe",
    "rundll32.exe",
    "mshta.exe",
];

pub fn acquire_native(
    _resolved: &crate::config::ResolvedRun,
    layout: &OutputLayout,
) -> Result<String> {
    enable_se_debug_privilege()?;
    let dump_dir = layout.raw_dir.join("memory_dumps");
    std::fs::create_dir_all(&dump_dir)?;

    let processes = snapshot_processes()?;
    let mut manifest_rows: Vec<String> = Vec::new();
    let mut dumped = 0usize;
    let mut skipped = 0usize;
    let mut stop_reason: Option<String> = None;

    for (pid, name) in processes {
        // 跳过 System Idle Process 与自身快照失败项。
        if pid == 0 {
            continue;
        }
        if let Some(reason) = stop_reason.as_ref() {
            manifest_rows.push(format!(
                "{pid},{name},,0,skipped:{reason}\n"
            ));
            skipped += 1;
            continue;
        }
        // 磁盘余量保护：不足 2GB 静态下限时停止继续转储，防止写满磁盘影响业务。
        // 查询失败（非常规文件系统）沿用旧行为：不设静态门，仅靠转储失败兜底。
        let free = disk_free_bytes(&dump_dir);
        if let Some(free) = free {
            if free < STATIC_FREE_FLOOR {
                stop_reason = Some(format!("disk_low({free} bytes free)"));
                manifest_rows.push(format!(
                    "{pid},{name},,0,skipped:disk_low({free} bytes free)\n"
                ));
                skipped += 1;
                continue;
            }
        }
        // 转储前体量估算：能查到进程内存时要求 free ≥ 1.5 × 估算值，
        // 否则按进程逐个跳过（登记原因），不再"先转储再看"。
        let process = open_process_for_dump(pid);
        if process == 0 {
            manifest_rows.push(format!(
                "{pid},{name},,0,skipped:OpenProcess({pid}) failed (access denied)\n"
            ));
            skipped += 1;
            continue;
        }
        if let (Some(free), Some(estimate)) = (free, estimate_dump_bytes(process)) {
            let required = estimate.saturating_mul(SPACE_HEADROOM_NUM) / SPACE_HEADROOM_DEN;
            if free < required {
                manifest_rows.push(format!(
                    "{pid},{name},,0,skipped:insufficient_space(estimate {estimate} bytes, need {required}, free {free})\n"
                ));
                skipped += 1;
                unsafe { CloseHandle(process) };
                continue;
            }
        }
        // 查不到内存信息或余量时：退化为静态 2GB 下限（已在上方校验）。
        let file_name = format!("{pid}_{}.dmp", sanitize_name(&name));
        let destination = dump_dir.join(&file_name);
        match dump_process_with_type(process, pid, &destination, MiniDumpWithFullMemory) {
            Ok(()) => {
                let size = std::fs::metadata(&destination)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let sensitive = SENSITIVE_PROCESSES.contains(&name.to_ascii_lowercase().as_str());
                manifest_rows.push(format!(
                    "{pid},{name},{file_name},{size},{}\n",
                    if sensitive { "sensitive_process" } else { "ok" }
                ));
                dumped += 1;
            }
            Err(error) => {
                manifest_rows.push(format!("{pid},{name},,{},skipped:{error}\n", 0));
                skipped += 1;
            }
        }
        unsafe { CloseHandle(process) };
        // 单进程转储后复查：剩余空间低于 1GB 即终止后续进程转储。
        if let Some(free) = disk_free_bytes(&dump_dir) {
            if free < POST_DUMP_FREE_FLOOR {
                stop_reason = Some(format!("post_dump_disk_low({free} bytes free)"));
            }
        }
    }

    let manifest = dump_dir.join("manifest.csv");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&manifest)
        .map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("create manifest: {error}"))
        })?;
    file.write_all(b"pid,name,dump_file,size_bytes,status\n")
        .and_then(|_| file.write_all(manifest_rows.join("").as_bytes()))
        .map_err(|error| {
            DumpallError::invalid_argument("memory-dump", format!("write manifest: {error}"))
        })?;

    Ok(format!(
        "native process-memory acquisition: {dumped} dump(s) written to raw/memory_dumps/, {skipped} skipped (protected/inaccessible/insufficient space{})",
        stop_reason.map(|reason| format!("; stopped early: {reason}")).unwrap_or_default()
    ))
}

/// 低影响 Windows 进程内存取证：只转储常见 Web/脚本宿主和 LOLBin，最多 8 个，
/// 使用 private RW + unloaded module 信息，不暂停目标进程，也不获取物理内存。
pub fn acquire_triage(
    _resolved: &crate::config::ResolvedRun,
    layout: &OutputLayout,
) -> Result<String> {
    enable_se_debug_privilege()?;
    let dump_dir = layout.raw_dir.join("memory_triage_processes");
    std::fs::create_dir_all(&dump_dir)?;
    let mut rows = Vec::new();
    let mut selected = 0usize;
    let mut stop_reason: Option<String> = None;
    for (pid, name) in snapshot_processes()? {
        if pid == 0
            || selected >= 8
            || !TRIAGE_PROCESSES.contains(&name.to_ascii_lowercase().as_str())
        {
            continue;
        }
        if let Some(reason) = stop_reason.as_ref() {
            rows.push(format!("{pid},{name},,0,skipped:{reason}\n"));
            continue;
        }
        let free = disk_free_bytes(&dump_dir);
        if let Some(free) = free {
            if free < STATIC_FREE_FLOOR {
                stop_reason = Some(format!("disk_low({free} bytes free)"));
                rows.push(format!(
                    "{pid},{name},,0,skipped:disk_low({free} bytes free)\n"
                ));
                continue;
            }
        }
        let process = open_process_for_dump(pid);
        if process == 0 {
            rows.push(format!(
                "{pid},{name},,0,skipped:OpenProcess({pid}) failed (access denied)\n"
            ));
            continue;
        }
        if let (Some(free), Some(estimate)) = (free, estimate_dump_bytes(process)) {
            let required = estimate.saturating_mul(SPACE_HEADROOM_NUM) / SPACE_HEADROOM_DEN;
            if free < required {
                rows.push(format!(
                    "{pid},{name},,0,skipped:insufficient_space(estimate {estimate} bytes, need {required}, free {free})\n"
                ));
                unsafe { CloseHandle(process) };
                continue;
            }
        }
        selected += 1;
        let file_name = format!("{pid}_{}.dmp", sanitize_name(&name));
        let destination = dump_dir.join(&file_name);
        let dump_type = MiniDumpWithPrivateReadWriteMemory
            | MiniDumpWithFullMemoryInfo
            | MiniDumpWithCodeSegs
            | MiniDumpWithDataSegs
            | MiniDumpWithUnloadedModules
            | MiniDumpWithThreadInfo;
        match dump_process_with_type(process, pid, &destination, dump_type) {
            Ok(()) => {
                let size = std::fs::metadata(&destination)
                    .map(|m| m.len())
                    .unwrap_or(0);
                rows.push(format!("{pid},{name},{file_name},{size},captured\n"));
            }
            Err(error) => rows.push(format!("{pid},{name},,0,skipped:{error}\n")),
        }
        unsafe { CloseHandle(process) };
        if let Some(free) = disk_free_bytes(&dump_dir) {
            if free < POST_DUMP_FREE_FLOOR {
                stop_reason = Some(format!("post_dump_disk_low({free} bytes free)"));
            }
        }
    }
    let manifest = dump_dir.join("manifest.csv");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&manifest)?;
    file.write_all(b"pid,name,dump_file,size_bytes,status\n")?;
    file.write_all(rows.join("").as_bytes())?;
    Ok(format!(
        "low-impact Windows process memory triage: selected {selected} process(es), output raw/memory_triage_processes/; no process suspension or physical-memory acquisition{}",
        stop_reason.map(|reason| format!("; stopped early: {reason}")).unwrap_or_default()
    ))
}

fn enable_se_debug_privilege() -> Result<()> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                "OpenProcessToken failed (admin required)",
            ));
        }
        let mut luid = windows_sys::Win32::Foundation::LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                "LookupPrivilegeValueW(SeDebugPrivilege) failed",
            ));
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let previous: *mut windows_sys::Win32::Security::TOKEN_PRIVILEGES = std::ptr::null_mut();
        let returned: *mut u32 = std::ptr::null_mut();
        let adjusted = AdjustTokenPrivileges(token, 0, &privileges, 0, previous, returned);
        // GetLastError 必须紧跟 AdjustTokenPrivileges 读取：CloseHandle 可能覆盖
        // 线程级 last-error，导致 ERROR_NOT_ALL_ASSIGNED 等失败被误判成功。
        let adjust_error = GetLastError();
        CloseHandle(token);
        if adjusted == 0 || adjust_error != ERROR_SUCCESS {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                "AdjustTokenPrivileges(SeDebugPrivilege) failed (admin required)",
            ));
        }
    }
    Ok(())
}

fn snapshot_processes() -> Result<Vec<(u32, String)>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                "CreateToolhelp32Snapshot failed",
            ));
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };
        let mut processes = Vec::new();
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let length = entry
                    .szExeFile
                    .iter()
                    .position(|ch| *ch == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
                processes.push((entry.th32ProcessID, name));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        Ok(processes)
    }
}

/// 以转储所需权限打开进程；失败返回 0（调用方按跳过登记）。
fn open_process_for_dump(pid: u32) -> HANDLE {
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) }
}

/// 估算进程转储落盘体量（字节）：GetProcessMemoryInfo 取提交内存
/// （PagefileUsage，即 CommitSize）与工作集的较大者。FullMemory 转储
/// 体量近似提交内存；PrivateUsage 在 EX 结构中与之等价。
/// 查询失败返回 None（调用方退化为静态空间下限）。
fn estimate_dump_bytes(process: HANDLE) -> Option<u64> {
    unsafe {
        let mut counters = PROCESS_MEMORY_COUNTERS_EX {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..std::mem::zeroed()
        };
        if GetProcessMemoryInfo(
            process,
            &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            counters.cb,
        ) == 0
        {
            return None;
        }
        let commit = counters.PagefileUsage as u64;
        let working = counters.WorkingSetSize as u64;
        Some(commit.max(working))
    }
}

fn dump_process_with_type(
    process: HANDLE,
    pid: u32,
    destination: &Path,
    dump_type: windows_sys::Win32::System::Diagnostics::Debug::MINIDUMP_TYPE,
) -> Result<()> {
    unsafe {
        if process == 0 {
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                format!("invalid process handle for pid {pid}"),
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(destination)
            .map_err(|error| {
                DumpallError::invalid_argument("memory-dump", format!("create dmp: {error}"))
            })?;
        // 用写入句柄的 OS 句柄值交给 MiniDumpWriteDump。
        let file_handle = std::os::windows::io::AsRawHandle::as_raw_handle(&file) as HANDLE;
        let ok = MiniDumpWriteDump(
            process,
            pid,
            file_handle,
            dump_type,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if ok == 0 {
            let _ = std::fs::remove_file(destination);
            return Err(DumpallError::invalid_argument(
                "memory-dump",
                format!("MiniDumpWriteDump({pid}) failed"),
            ));
        }
    }
    Ok(())
}

/// 目录所在磁盘剩余空间（GetDiskFreeSpaceExW）。
fn disk_free_bytes(directory: &Path) -> Option<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = directory
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut free: u64 = 0;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        Some(free)
    } else {
        None
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
