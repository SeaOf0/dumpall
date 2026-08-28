//! 外置内存获取工具驱动：调用用户指定的工具（如 avml / winpmem），
//! 输出到结果目录 raw/memory.bin，登记哈希。dumpall 自身不做内核级内存获取。

use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use sha2::Digest;

use crate::config::ResolvedRun;
use crate::error::{DumpallError, Result};
use crate::output::paths::OutputLayout;

/// 单次内存 dump 的目标文件名（位于 raw/ 目录，作为 sidecar 不压入 zip）。
pub const MEMORY_DUMP_NAME: &str = "memory.bin";

pub fn run_memory_tool(resolved: &ResolvedRun, layout: &OutputLayout) -> Result<String> {
    let tool = resolved
        .memory_tool
        .as_ref()
        .ok_or_else(|| DumpallError::invalid_argument("memory-tool", "memory tool path missing"))?;
    if !tool.is_file() {
        return Err(DumpallError::invalid_argument(
            "memory-tool",
            format!(
                "memory tool not found or not a regular file: {}",
                tool.display()
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tool)?.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(DumpallError::invalid_argument(
                "memory-tool",
                format!(
                    "memory tool is group/other writable; refusing to execute: {}",
                    tool.display()
                ),
            ));
        }
    }
    std::fs::create_dir_all(&layout.raw_dir)?;
    let output = layout.raw_dir.join(MEMORY_DUMP_NAME);
    let mut child = Command::new(tool).arg(&output).spawn().map_err(|error| {
        DumpallError::invalid_argument(
            "memory-tool",
            format!("memory tool could not be executed: {error}"),
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            DumpallError::invalid_argument(
                "memory-tool",
                format!("memory tool wait failed: {error}"),
            )
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DumpallError::invalid_argument(
                "memory-tool",
                "memory tool exceeded 30 minute timeout and was terminated",
            ));
        }
        thread::sleep(Duration::from_millis(250));
    };
    if !status.success() {
        return Err(DumpallError::invalid_argument(
            "memory-tool",
            format!("memory tool exited with status {status}"),
        ));
    }
    let size = std::fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Err(DumpallError::invalid_argument(
            "memory-tool",
            "memory tool exited successfully but produced no output",
        ));
    }
    let hash = sha256_file(&output).unwrap_or_default();
    Ok(format!(
        "memory acquisition completed via {}: output raw/{MEMORY_DUMP_NAME}, {size} bytes, sha256={hash}",
        tool.display()
    ))
}

/// 对可能达到物理内存规模的镜像分块计算哈希，避免把整个文件载入进程内存。
pub(crate) fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    // 1MB 缓冲放堆上:Windows 主线程默认栈仅 1-2MB,栈上大数组会在函数序言
    // 直接撞栈守护页(STATUS_STACK_OVERFLOW 0xc00000fd)。
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
