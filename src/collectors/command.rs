use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::writers;

use super::collection_error;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CAPTURE_BYTES: usize = 32 * 1024 * 1024;

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    timed_out: bool,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: &'static str,
    pub args: Vec<String>,
    pub display: String,
}

impl CommandSpec {
    pub fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let display = std::iter::once(program.to_string())
            .chain(args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ");
        Self {
            program,
            args,
            display,
        }
    }

    #[cfg(windows)]
    pub fn powershell(script: impl Into<String>) -> Self {
        let script = format!(
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); {}",
            script.into()
        );
        Self::new(
            "powershell.exe",
            [
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                script,
            ],
        )
    }

    /// 中文 Windows 默认控制台代码页是 GBK(936)：certutil/reg 等原生命令的
    /// 本地化输出经 from_utf8_lossy 解码会被破坏。经 cmd.exe 先 `chcp 65001`
    /// 切到 UTF-8 再执行命令，保证子进程输出为 UTF-8。
    /// 供无法设置 [Console]::OutputEncoding 的直跑原生命令使用。
    #[cfg(windows)]
    pub fn cmd_utf8(command_line: impl Into<String>) -> Self {
        let script = format!("chcp 65001 >nul & {}", command_line.into());
        Self::new("cmd.exe", ["/c".to_string(), script])
    }
}

pub fn collect_text_command(
    source: &str,
    output_path: &Path,
    fallback_content: &str,
    commands: &[CommandSpec],
    errors: &mut Vec<CollectionError>,
    redact: bool,
) -> Result<()> {
    for command in commands {
        match run_bounded(command) {
            Ok(output) if output.status.success() && !output.timed_out => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !output.stderr.is_empty() {
                    errors.push(collection_error(
                        source,
                        output_path.display().to_string(),
                        command.display.clone(),
                        "command exited successfully but emitted stderr; result may be partial",
                        Some(
                            String::from_utf8_lossy(&output.stderr)
                                .lines()
                                .find(|line| !line.trim().is_empty())
                                .unwrap_or("stderr without readable text")
                                .chars()
                                .take(300)
                                .collect::<String>(),
                        ),
                    ));
                }
                if output.stdout_truncated || output.stderr_truncated {
                    errors.push(collection_error(
                        source,
                        output_path.display().to_string(),
                        command.display.clone(),
                        "command output exceeded the bounded capture limit; retained output is partial",
                        Some(format!(
                            "stdout_truncated={}, stderr_truncated={}, per_stream_limit_bytes={MAX_CAPTURE_BYTES}",
                            output.stdout_truncated, output.stderr_truncated
                        )),
                    ));
                }
                if stdout.trim().is_empty() {
                    errors.push(collection_error(
                        source,
                        output_path.display().to_string(),
                        command.display.clone(),
                        "command succeeded but produced no output; fallback header written",
                        Some("Verify permissions, command availability, and OS support; an empty result is not proof that no objects exist.".to_string()),
                    ));
                    writers::write_text(output_path, fallback_content)?;
                } else {
                    let content = if redact {
                        crate::safety::redact_text(&stdout)
                    } else {
                        stdout.to_string()
                    };
                    writers::write_text(output_path, &content)?;
                }
                return Ok(());
            }
            Ok(output) => {
                errors.push(collection_error(
                    source,
                    output_path.display().to_string(),
                    command.display.clone(),
                    if output.timed_out {
                        format!(
                            "command exceeded the {} second timeout and was terminated",
                            COMMAND_TIMEOUT.as_secs()
                        )
                    } else {
                        format!("command exited with status {}", output.status)
                    },
                    Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
                ));
            }
            Err(error) => {
                errors.push(collection_error(
                    source,
                    output_path.display().to_string(),
                    command.display.clone(),
                    "command could not be started",
                    Some(error.to_string()),
                ));
            }
        }
    }

    writers::write_text(output_path, fallback_content)?;
    Ok(())
}

fn run_bounded(command: &CommandSpec) -> std::io::Result<BoundedOutput> {
    let mut child = Command::new(resolve_program(command.program))
        .args(&command.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout must be available");
    let stderr = child.stderr.take().expect("piped stderr must be available");
    let stdout_reader = std::thread::spawn(move || drain_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || drain_bounded(stderr));

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if started.elapsed() >= COMMAND_TIMEOUT {
            let _ = child.kill();
            break (child.wait()?, true);
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let (stdout, stdout_truncated) = stdout_reader.join().unwrap_or_default();
    let (stderr, stderr_truncated) = stderr_reader.join().unwrap_or_default();
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

fn drain_bounded(mut reader: impl std::io::Read) -> (Vec<u8>, bool) {
    let mut retained = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let Ok(read) = reader.read(&mut buffer) else {
            break;
        };
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(retained.len());
        let keep = remaining.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    (retained, truncated)
}

#[cfg(windows)]
fn resolve_program(program: &str) -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    match program.to_ascii_lowercase().as_str() {
        "powershell.exe" => root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        "cmd.exe" | "certutil.exe" | "reg.exe" => root.join("System32").join(program),
        _ => std::path::PathBuf::from(program),
    }
}

#[cfg(not(windows))]
fn resolve_program(program: &str) -> &std::path::Path {
    Path::new(program)
}
