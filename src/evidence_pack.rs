use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crc32fast::Hasher as Crc32Hasher;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ResolvedRun;
use crate::error::{DumpallError, Result};
use crate::model::PackFormat;
use crate::output::manifest::RunManifest;
use crate::output::paths::OutputLayout;
use crate::output::writers;

const PACK_NOTE: &str = "证据包包含摘要、索引和哈希，不是完整取证镜像。";

#[derive(Debug, Clone)]
pub struct EvidencePackReport {
    pub files_indexed: usize,
    pub package_path: PathBuf,
    pub package_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct PackManifest {
    tool: String,
    version: String,
    created_at: String,
    host: String,
    result_dir: String,
    redact: bool,
    offline: bool,
    pack_format: String,
    package_file: String,
    package_sha256: String,
    package_size_bytes: u64,
    files: Vec<PackFile>,
    rules_checksum: Option<String>,
    notes: String,
}

#[derive(Debug, Clone, Serialize)]
struct PackFile {
    path: String,
    sha256: String,
    size_bytes: u64,
    kind: &'static str,
    description: &'static str,
    required: bool,
}

#[derive(Debug, Clone)]
struct PackCandidate {
    absolute: PathBuf,
    relative: String,
    kind: &'static str,
    description: &'static str,
    required: bool,
}

#[derive(Debug, Clone)]
struct StagedFile {
    absolute: PathBuf,
    relative: String,
    size_bytes: u64,
    sha256: String,
}

pub fn generate(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    manifest: &RunManifest,
) -> Result<EvidencePackReport> {
    let mut files = collect_pack_files(layout, resolved)?;
    let include_raw = resolved.mode == crate::model::RunMode::Triage
        || resolved.profile == crate::profile::ScanProfile::Triage;
    write_evidence_index(layout, &files, include_raw)?;
    write_review_guide(layout, resolved, &files)?;
    files.push(stage_existing_file(
        &layout.evidence_index_csv,
        "evidence_pack/evidence_index.csv",
    )?);
    files.push(stage_existing_file(
        &layout.evidence_index_json,
        "evidence_pack/evidence_index.json",
    )?);
    files.push(stage_existing_file(
        &layout.review_guide,
        "evidence_pack/review_guide.md",
    )?);

    let package_path = package_path(layout, resolved.pack_format);
    let pack_result = match resolved.pack_format {
        PackFormat::Zip => write_zip_package(&package_path, &files),
        PackFormat::Tar => write_tar_package(&package_path, &files),
    };
    // 打包期间任一源文件与登记录入时不一致 → 记入 collection_errors 并整包失败
    //（取证链完整性优先：坏包不如无包）。
    let streamed = match pack_result {
        Ok(streamed) => streamed,
        Err(error) => {
            record_pack_failure(layout, &error);
            let _ = fs::remove_file(&package_path);
            return Err(error);
        }
    };
    // 包内每个字节的哈希清单来自打包单遍流式读取，与包内容严格同源。
    let mut hash_rows: Vec<StagedFile> = files
        .iter()
        .zip(streamed.iter())
        .map(|(file, entry)| StagedFile {
            absolute: file.absolute.clone(),
            relative: file.relative.clone(),
            size_bytes: entry.written,
            sha256: entry.sha256.clone(),
        })
        .collect();

    let package_size_bytes = fs::metadata(&package_path)?.len();
    let package_sha256 = sha256_file_hex(&package_path)?;

    let rules_checksum = read_rules_checksum(&layout.rules_manifest);
    let pack_manifest = PackManifest {
        tool: manifest.tool.clone(),
        version: manifest.version.clone(),
        created_at: crate::time_utils::now_iso(),
        host: manifest.hostname.clone(),
        result_dir: layout.root.display().to_string(),
        redact: manifest.redact,
        offline: manifest.offline,
        pack_format: resolved.pack_format.as_str().to_string(),
        package_file: relative_to_root(layout, &package_path),
        package_sha256: format!("sha256:{package_sha256}"),
        package_size_bytes,
        files: hash_rows
            .iter()
            .map(|file| PackFile {
                path: file.relative.clone(),
                sha256: format!("sha256:{}", file.sha256),
                size_bytes: file.size_bytes,
                kind: "packaged_artifact",
                description: "已打包证据文件",
                required: true,
            })
            .collect(),
        rules_checksum,
        notes: PACK_NOTE.to_string(),
    };
    writers::write_json_pretty(&layout.pack_manifest, &pack_manifest)?;

    hash_rows.push(StagedFile {
        absolute: package_path.clone(),
        relative: relative_to_root(layout, &package_path),
        size_bytes: package_size_bytes,
        sha256: package_sha256.clone(),
    });
    hash_rows.push(StagedFile {
        absolute: layout.pack_manifest.clone(),
        relative: relative_to_root(layout, &layout.pack_manifest),
        size_bytes: fs::metadata(&layout.pack_manifest)?.len(),
        sha256: sha256_file_hex(&layout.pack_manifest)?,
    });
    write_pack_hashes(layout, &hash_rows)?;

    Ok(EvidencePackReport {
        files_indexed: hash_rows.len(),
        package_path,
        package_sha256: format!("sha256:{package_sha256}"),
    })
}

fn collect_pack_files(layout: &OutputLayout, resolved: &ResolvedRun) -> Result<Vec<StagedFile>> {
    let mut files = Vec::new();
    for candidate in pack_candidates(
        layout,
        resolved.mode == crate::model::RunMode::Triage
            || resolved.profile == crate::profile::ScanProfile::Triage,
    ) {
        if !candidate.absolute.is_file() {
            if candidate.required {
                return Err(DumpallError::Message(format!(
                    "required evidence-pack source is missing: {}",
                    candidate.absolute.display()
                )));
            }
            continue;
        }
        files.push(StagedFile {
            size_bytes: fs::metadata(&candidate.absolute)?.len(),
            sha256: sha256_file_hex(&candidate.absolute)?,
            absolute: candidate.absolute,
            relative: candidate.relative.to_string(),
        });
    }
    Ok(files)
}

fn stage_existing_file(absolute: &Path, relative: &'static str) -> Result<StagedFile> {
    Ok(StagedFile {
        absolute: absolute.to_path_buf(),
        relative: relative.to_string(),
        size_bytes: fs::metadata(absolute)?.len(),
        sha256: sha256_file_hex(absolute)?,
    })
}

fn pack_candidates(layout: &OutputLayout, include_raw: bool) -> Vec<PackCandidate> {
    let mut candidates = vec![
        candidate(&layout.manifest, "manifest.json", "run", "运行清单", true),
        candidate(
            &layout.html_report,
            "reports/report.html",
            "report",
            "分析人员首读 HTML 报告",
            true,
        ),
        candidate(
            &layout.summary_report,
            "reports/summary_report.md",
            "report",
            "Markdown 摘要报告",
            true,
        ),
        candidate(
            &layout.runtime_report,
            "reports/runtime_report.md",
            "report",
            "运行时组件报告",
            false,
        ),
        candidate(
            &layout.host_events_report,
            "reports/host_events_report.md",
            "report",
            "主机事件报告",
            false,
        ),
        candidate(
            &layout.container_report,
            "reports/container_report.md",
            "report",
            "容器证据报告",
            false,
        ),
        candidate(
            &layout.timeline_csv,
            "timeline/timeline.csv",
            "timeline",
            "统一时间线 CSV",
            true,
        ),
        candidate(
            &layout.attack_chains,
            "timeline/attack_chains.md",
            "timeline",
            "攻击链复核摘要",
            false,
        ),
        candidate(
            &layout.high_risk_events,
            "findings/high_risk_events.csv",
            "finding",
            "高危发现表",
            true,
        ),
        candidate(
            &layout.findings_csv,
            "findings/findings.csv",
            "finding",
            "全部发现 CSV",
            true,
        ),
        candidate(
            &layout.evidence_gaps,
            "findings/evidence_gaps.csv",
            "finding",
            "证据缺口与采集覆盖告警",
            true,
        ),
        candidate(
            &layout.updated_files,
            "findings/updated_files.csv",
            "filesystem",
            "系统文件修改时间线",
            false,
        ),
        candidate(
            &layout.memory_triage,
            "findings/memory_triage.csv",
            "memory",
            "低影响进程内存映射与片段清单",
            false,
        ),
        candidate(
            &layout.memory_strings,
            "findings/memory_strings.csv",
            "memory",
            "内存字符串线索",
            false,
        ),
        candidate(
            &layout.collection_errors,
            "collection/collection_errors.csv",
            "collection",
            "采集错误",
            true,
        ),
        candidate(
            &layout.parse_errors,
            "collection/parse_errors.csv",
            "collection",
            "解析错误",
            true,
        ),
        candidate(
            &layout.file_hashes,
            "evidence/file_hashes.csv",
            "hash",
            "静态文件哈希清单",
            false,
        ),
        candidate(
            &layout.evidence_copy_manifest,
            "evidence/evidence_copy_manifest.csv",
            "evidence_copy",
            "发现项源文件复制清单",
            false,
        ),
        candidate(
            &layout.rules_manifest,
            "rules_used/rules_manifest.json",
            "rule",
            "实际生效规则清单",
            true,
        ),
        candidate(
            &layout.effective_allowlist,
            "rules_used/effective_allowlist.toml",
            "rule",
            "实际生效白名单副本",
            true,
        ),
        candidate(
            &layout.sarif_report,
            "reports/dumpall.sarif",
            "report",
            "SARIF 报告",
            false,
        ),
    ];
    if include_raw {
        append_raw_candidates(layout, &mut candidates);
        append_evidence_candidates(layout, &mut candidates);
    }
    candidates
}

/// triage 复制的发现项源文件随证据包交付；受限凭据/私钥和完整内存仍留在 sidecar。
fn append_evidence_candidates(layout: &OutputLayout, candidates: &mut Vec<PackCandidate>) {
    const MAX_EVIDENCE_PACK_FILES: usize = 5_000;
    let mut stack = vec![layout.suspicious_evidence_dir.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if candidates.len() >= MAX_EVIDENCE_PACK_FILES {
                return;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = match path.strip_prefix(&layout.root) {
                Ok(value) => value.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            if is_sensitive_evidence(&relative) {
                continue;
            }
            candidates.push(PackCandidate {
                absolute: path,
                relative,
                kind: "evidence_copy",
                description: "发现项源文件副本",
                required: false,
            });
        }
    }
}

fn candidate(
    absolute: &Path,
    relative: &'static str,
    kind: &'static str,
    description: &'static str,
    required: bool,
) -> PackCandidate {
    PackCandidate {
        absolute: absolute.to_path_buf(),
        relative: relative.to_string(),
        kind,
        description,
        required,
    }
}

/// Triage 包含关键 raw 日志/配置副本，但不把完整物理内存或全量进程 dmp
/// 自动塞进压缩包；这类文件通常体积巨大且包含凭据，应通过受控 sidecar 交付。
fn append_raw_candidates(layout: &OutputLayout, candidates: &mut Vec<PackCandidate>) {
    const MAX_RAW_PACK_FILES: usize = 2_500;
    let mut stack = vec![layout.raw_dir.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if candidates.len() >= MAX_RAW_PACK_FILES {
                return;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = match path.strip_prefix(&layout.root) {
                Ok(value) => value.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            if relative == "raw/memory.bin"
                || (relative.starts_with("raw/memory_dumps/") && relative.ends_with(".dmp"))
                || (relative.starts_with("raw/memory_triage_processes/")
                    && relative.ends_with(".dmp"))
                || is_sensitive_raw(&relative)
            {
                continue;
            }
            candidates.push(PackCandidate {
                absolute: path,
                relative,
                kind: "raw",
                description: "triage 原始日志/配置副本",
                required: false,
            });
        }
    }
}

/// 凭据/私钥类原始副本仍保留在受限 raw/ sidecar，但不随 triage ZIP 扩散。
fn is_sensitive_raw(relative: &str) -> bool {
    let path = relative.to_ascii_lowercase();
    path == "raw/etc/shadow"
        || path == "raw/etc/gshadow"
        || path.ends_with("/.ssh/id_rsa")
        || path.ends_with("/.ssh/id_ed25519")
        || path.ends_with("/.ssh/id_ecdsa")
        || path.ends_with("/.ssh/id_dsa")
        || path.ends_with("/.ssh/authorized_keys")
        || path.ends_with("/.ssh/authorized_keys2")
        || path.ends_with("/sam")
        || path.ends_with("/security")
        || path.ends_with("/system")
        || path.ends_with("/software")
}

fn is_sensitive_evidence(relative: &str) -> bool {
    let source_like = relative.replacen("evidence/suspicious_files/", "raw/", 1);
    let lower = relative.to_ascii_lowercase();
    is_sensitive_raw(&source_like)
        || lower.ends_with(".dmp")
        || lower.ends_with(".dump")
        || lower.ends_with(".core")
}

fn write_evidence_index(
    layout: &OutputLayout,
    staged: &[StagedFile],
    include_raw: bool,
) -> Result<()> {
    let candidates = pack_candidates(layout, include_raw);
    let mut rows = Vec::new();
    for candidate in candidates {
        if let Some(file) = staged
            .iter()
            .find(|file| file.relative == candidate.relative)
        {
            rows.push(PackFile {
                path: file.relative.clone(),
                sha256: format!("sha256:{}", file.sha256),
                size_bytes: file.size_bytes,
                kind: candidate.kind,
                description: candidate.description,
                required: candidate.required,
            });
        }
    }

    writers::write_json_pretty(&layout.evidence_index_json, &rows)?;

    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&layout.evidence_index_csv)?;
    writer.write_record([
        "path",
        "kind",
        "description",
        "source",
        "required",
        "sha256",
        "size_bytes",
    ])?;
    for row in rows {
        let required = if row.required { "true" } else { "false" };
        let size_bytes = row.size_bytes.to_string();
        // 路径来自被检主机文件名（可能以 = + - @ 开头），套 CSV 公式注入防护。
        writer.write_record([
            writers::csv_safe_cell(&row.path).as_str(),
            row.kind,
            row.description,
            "dumpall_output",
            required,
            row.sha256.as_str(),
            size_bytes.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_review_guide(
    layout: &OutputLayout,
    resolved: &ResolvedRun,
    staged: &[StagedFile],
) -> Result<()> {
    let mut guide = String::new();
    guide.push_str("# 证据包复核指南\n\n");
    guide.push_str("## 范围\n\n");
    guide.push_str("- 发现项是供人工复核的可疑证据，不是入侵定论。\n");
    guide.push_str("- 证据包包含摘要、索引、规则元数据、哈希和短证据引用。\n");
    if resolved.mode == crate::model::RunMode::Triage
        || resolved.profile == crate::profile::ScanProfile::Triage
    {
        guide.push_str("- triage 包含 raw/ 下的日志与配置副本，以及 evidence/suspicious_files/ 下的发现项源文件副本；凭据/私钥、完整物理内存 raw/memory.bin 和逐进程 .dmp 保留为受限 sidecar，不自动进入压缩包。\n\n");
    } else {
        guide.push_str("- 默认不包含完整原始日志、内存镜像、磁盘镜像或容器文件系统。\n\n");
    }
    guide.push_str("## 安全边界\n\n");
    guide.push_str(&format!(
        "- 离线模式：{}\n",
        if resolved.safety.offline {
            "是"
        } else {
            "否"
        }
    ));
    guide.push_str(&format!(
        "- 脱敏启用：{}\n",
        if resolved.safety.redact { "是" } else { "否" }
    ));
    guide.push_str("- 证据包生成过程不执行修复、删除、服务变更、容器 exec、JVM attach、heap dump 或主动扫描。\n\n");
    guide.push_str("## 校验\n\n");
    guide.push_str("- 重新计算 `evidence_pack/pack_hashes.csv` 中列出的文件 SHA256。\n");
    guide.push_str("- 共享或归档前，确认 `evidence_pack/pack_manifest.json` 中记录的包哈希。\n");
    guide.push_str("- 将“未发现证据”解读为“正常”前，先复核 `findings/evidence_gaps.csv`。\n\n");
    guide.push_str("## 打包文件\n\n");
    for file in staged {
        guide.push_str(&format!(
            "- `{}` ({} bytes, sha256:{})\n",
            file.relative, file.size_bytes, file.sha256
        ));
    }
    writers::write_text(&layout.review_guide, &guide)
}

fn write_pack_hashes(layout: &OutputLayout, rows: &[StagedFile]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(&layout.pack_hashes)?;
    writer.write_record(["path", "sha256", "size_bytes"])?;
    for row in rows {
        let sha256 = format!("sha256:{}", row.sha256);
        let size_bytes = row.size_bytes.to_string();
        writer.write_record([
            writers::csv_safe_cell(&row.relative).as_str(),
            sha256.as_str(),
            size_bytes.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn package_path(layout: &OutputLayout, format: PackFormat) -> PathBuf {
    let stamp = crate::time_utils::format_result_stamp(crate::time_utils::now());
    match format {
        PackFormat::Zip => layout
            .evidence_pack_dir
            .join(format!("dumpall_evidence_{stamp}.zip")),
        PackFormat::Tar => layout
            .evidence_pack_dir
            .join(format!("dumpall_evidence_{stamp}.tar")),
    }
}

/// 打包单遍流式结果：同一遍读取同时产出写入包内的字节数、SHA256 与 CRC32，
/// 保证哈希清单与包结构描述的是同一时间点的同一份内容。
#[derive(Debug, Clone)]
struct PackStreamed {
    sha256: String,
    crc32: u32,
    written: u64,
}

/// 单遍流式复制：打开一次，边读边同时喂 SHA256+CRC32 并写入包体；
/// 实际读到的字节数或内容与登记录入（staged）不一致时报错并中止打包。
fn stream_copy_and_hash(
    input: &mut File,
    output: &mut impl Write,
    staged: &StagedFile,
) -> Result<PackStreamed> {
    let mut sha256 = Sha256::new();
    let mut crc32 = Crc32Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
        crc32.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
        written += read as u64;
    }
    if written != staged.size_bytes {
        return Err(DumpallError::Message(format!(
            "evidence-pack source changed while packing (size mismatch): {} (registered {} bytes, read {} bytes)",
            staged.absolute.display(),
            staged.size_bytes,
            written
        )));
    }
    let digest = sha256.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    if hex != staged.sha256 {
        return Err(DumpallError::Message(format!(
            "evidence-pack source changed while packing (sha256 mismatch): {}",
            staged.absolute.display()
        )));
    }
    Ok(PackStreamed {
        sha256: hex,
        crc32: crc32.finalize(),
        written,
    })
}

/// ZIP DOS 时间（本地当前时间）：date = (年-1980)<<9|月<<5|日，time = 时<<11|分<<5|秒/2。
/// 年份超出 DOS 表示范围（1980..=2107）时保持 0。
fn dos_date_time_now() -> (u16, u16) {
    let now = crate::time_utils::now();
    let year = now.year();
    if !(1980..=2107).contains(&year) {
        return (0, 0);
    }
    let date = (((year - 1980) as u16) << 9)
        | (u16::from(u8::from(now.month())) << 5)
        | u16::from(now.day());
    let time = (u16::from(now.hour()) << 11)
        | (u16::from(now.minute()) << 5)
        | (u16::from(now.second()) / 2);
    (time, date)
}

fn write_zip_package(path: &Path, files: &[StagedFile]) -> Result<Vec<PackStreamed>> {
    let mut output = File::create(path)?;
    let mut central = Vec::new();
    let mut streamed = Vec::new();
    let mut offset = 0u64;
    let (dos_time, dos_date) = dos_date_time_now();

    for file in files {
        if file.size_bytes > u32::MAX as u64 {
            return Err(DumpallError::Message(format!(
                "evidence-pack file exceeds ZIP32 limit: {}",
                file.absolute.display()
            )));
        }
        let name = normalize_archive_path(&file.relative);
        let name_bytes = name.as_bytes();
        validate_zip_name(name_bytes)?;

        // stored（无压缩）条目：本地头先写占位 CRC，单遍流式写完数据后回填真实值。
        let local_header_offset = offset;
        output.write_all(&0x0403_4b50u32.to_le_bytes())?;
        output.write_all(&20u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&dos_time.to_le_bytes())?;
        output.write_all(&dos_date.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&(file.size_bytes as u32).to_le_bytes())?;
        output.write_all(&(file.size_bytes as u32).to_le_bytes())?;
        output.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(name_bytes)?;

        let mut input = File::open(&file.absolute)?;
        let entry = stream_copy_and_hash(&mut input, &mut output, file)?;
        let data_end = output.stream_position()?;
        output.seek(SeekFrom::Start(local_header_offset + 14))?;
        output.write_all(&entry.crc32.to_le_bytes())?;
        output.seek(SeekFrom::Start(data_end))?;

        central.push(ZipCentralEntry {
            name,
            crc32: entry.crc32,
            compressed_size: entry.written as u32,
            uncompressed_size: entry.written as u32,
            local_header_offset: local_header_offset as u32,
        });
        streamed.push(entry);
        offset = data_end;
    }

    let central_offset = offset;
    for entry in &central {
        let name_bytes = entry.name.as_bytes();
        output.write_all(&0x0201_4b50u32.to_le_bytes())?;
        output.write_all(&20u16.to_le_bytes())?;
        output.write_all(&20u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&dos_time.to_le_bytes())?;
        output.write_all(&dos_date.to_le_bytes())?;
        output.write_all(&entry.crc32.to_le_bytes())?;
        output.write_all(&entry.compressed_size.to_le_bytes())?;
        output.write_all(&entry.uncompressed_size.to_le_bytes())?;
        output.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u16.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&entry.local_header_offset.to_le_bytes())?;
        output.write_all(name_bytes)?;
    }
    let central_size = output.stream_position()? - central_offset;
    // EOCD 的偏移/长度字段只有 32 位：整包超过 ZIP32 上限时显式报错，
    // 提示改用 tar，而不是静默截断成坏包。
    if central_offset > u32::MAX as u64 || central_size > u32::MAX as u64 {
        return Err(DumpallError::Message(format!(
            "evidence-pack zip exceeds the ZIP32 4GiB limit (payload offset {central_offset} bytes, central directory {central_size} bytes); rerun with --pack-format tar"
        )));
    }
    output.write_all(&0x0605_4b50u32.to_le_bytes())?;
    output.write_all(&0u16.to_le_bytes())?;
    output.write_all(&0u16.to_le_bytes())?;
    output.write_all(&(central.len() as u16).to_le_bytes())?;
    output.write_all(&(central.len() as u16).to_le_bytes())?;
    output.write_all(&(central_size as u32).to_le_bytes())?;
    output.write_all(&(central_offset as u32).to_le_bytes())?;
    output.write_all(&0u16.to_le_bytes())?;
    output.flush()?;
    Ok(streamed)
}

#[derive(Debug)]
struct ZipCentralEntry {
    name: String,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

fn validate_zip_name(name: &[u8]) -> Result<()> {
    if name.len() > u16::MAX as usize {
        return Err(DumpallError::Message(
            "evidence-pack zip entry name is too long".to_string(),
        ));
    }
    Ok(())
}

fn write_tar_package(path: &Path, files: &[StagedFile]) -> Result<Vec<PackStreamed>> {
    let mut output = File::create(path)?;
    let mut streamed = Vec::new();
    for file in files {
        let name = normalize_archive_path(&file.relative);
        let mut header = [0u8; 512];
        if write_tar_name(&mut header, &name).is_err() {
            // ustar name(100)/prefix(155) 都装不下(深层或含中文等多字节文件名,
            // 每个汉字 3 字节):先写 GNU longname 扩展条目(typeflag 'L')承载
            // 完整路径,再写截断显示名的真实头。GNU tar/bsdtar/7-Zip 等通用
            // 解包器都支持,证据文件名零截断;不再让单个长名条目毁掉整个包。
            write_tar_longname_entry(&mut output, &name)?;
            write_tar_name_truncated(&mut header, &name);
        }
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], file.size_bytes);
        write_octal(&mut header[136..148], 0);
        for byte in &mut header[148..156] {
            *byte = b' ';
        }
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>() as u64;
        write_checksum(&mut header[148..156], checksum);
        output.write_all(&header)?;
        // 单遍流式：打开一次，边读边喂 SHA256+CRC32 并写包。
        let mut input = File::open(&file.absolute)?;
        let entry = stream_copy_and_hash(&mut input, &mut output, file)?;
        let padding = (512 - (entry.written % 512)) % 512;
        if padding > 0 {
            output.write_all(&vec![0u8; padding as usize])?;
        }
        streamed.push(entry);
    }
    output.write_all(&[0u8; 1024])?;
    output.flush()?;
    Ok(streamed)
}

/// GNU longname 伪条目:承载超长路径本体,其后紧跟真实文件条目。
fn write_tar_longname_entry(output: &mut File, name: &str) -> Result<()> {
    let mut header = [0u8; 512];
    let marker = b"././@LongLink";
    header[..marker.len()].copy_from_slice(marker);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    // 内容 = 路径 + 结尾 NUL。
    write_octal(&mut header[124..136], name.len() as u64 + 1);
    write_octal(&mut header[136..148], 0);
    for byte in &mut header[148..156] {
        *byte = b' ';
    }
    header[156] = b'L';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>() as u64;
    write_checksum(&mut header[148..156], checksum);
    output.write_all(&header)?;
    output.write_all(name.as_bytes())?;
    output.write_all(&[0u8])?;
    let padding = (512 - ((name.len() + 1) % 512)) % 512;
    if padding > 0 {
        output.write_all(&vec![0u8; padding])?;
    }
    Ok(())
}

/// longname 后的真实头:显示名截到 100 字节内(字符边界安全),真实路径以
/// longname 条目为准。
fn write_tar_name_truncated(header: &mut [u8; 512], name: &str) {
    let mut end = name.len().min(100);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    let bytes = name[..end].as_bytes();
    header[..bytes.len()].copy_from_slice(bytes);
}

fn write_tar_name(header: &mut [u8; 512], name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() <= 100 {
        header[..bytes.len()].copy_from_slice(bytes);
        return Ok(());
    }
    if bytes.len() <= 255 {
        if let Some(split) = name.rfind('/') {
            let prefix = &name[..split];
            let suffix = &name[split + 1..];
            let prefix_bytes = prefix.as_bytes();
            let suffix_bytes = suffix.as_bytes();
            if prefix_bytes.len() <= 155 && suffix_bytes.len() <= 100 {
                header[..suffix_bytes.len()].copy_from_slice(suffix_bytes);
                header[345..345 + prefix_bytes.len()].copy_from_slice(prefix_bytes);
                return Ok(());
            }
        }
    }
    Err(DumpallError::Message(format!(
        "evidence-pack tar entry path is too long: {name}"
    )))
}

fn write_octal(target: &mut [u8], value: u64) {
    target.fill(0);
    let width = target.len().saturating_sub(1);
    let encoded = format!("{value:0width$o}");
    let bytes = encoded.as_bytes();
    let start = width.saturating_sub(bytes.len());
    target[start..start + bytes.len()].copy_from_slice(bytes);
}

fn write_checksum(target: &mut [u8], value: u64) {
    target.fill(0);
    let encoded = format!("{value:06o}\0 ");
    target[..encoded.len()].copy_from_slice(encoded.as_bytes());
}

/// 打包失败（源文件与登记录入不一致等取证链完整性问题）时，
/// 将错误追加到 collection/collection_errors.csv 留痕；尽力而为，不影响错误传播。
fn record_pack_failure(layout: &OutputLayout, error: &DumpallError) {
    use std::fs::OpenOptions;
    let row = crate::collectors::collection_error(
        "evidence_pack",
        relative_to_root(layout, &layout.evidence_pack_dir),
        "package",
        "evidence pack aborted: packaged bytes no longer match registered file state",
        Some(error.to_string()),
    );
    let append_row = |file: &mut File| {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);
        let _ = writer.write_record([
            row.timestamp.as_str(),
            row.source.as_str(),
            row.path.as_str(),
            row.operation.as_str(),
            row.message.as_str(),
            row.detail.as_deref().unwrap_or_default(),
        ]);
        let _ = writer.flush();
    };
    if layout.collection_errors.is_file() {
        if let Ok(mut file) = OpenOptions::new().append(true).open(&layout.collection_errors) {
            append_row(&mut file);
        }
        return;
    }
    let Ok(mut file) = File::create(&layout.collection_errors) else {
        return;
    };
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(&mut file);
    let _ = writer.write_record([
        "timestamp", "source", "path", "operation", "message", "detail",
    ]);
    let _ = writer.flush();
    drop(writer);
    append_row(&mut file);
}

fn normalize_archive_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches('/')
        .trim_start_matches("./")
        .to_string()
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    Ok(output)
}

fn relative_to_root(layout: &OutputLayout, path: &Path) -> String {
    path.strip_prefix(&layout.root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn read_rules_checksum(path: &Path) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    value
        .get("checksum")
        .and_then(|checksum| checksum.as_str())
        .map(str::to_string)
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn tar_pack_supports_long_cjk_entry_names() {
        // 中文每字 3 字节:构造单段就超过 ustar name(100)/prefix(155) 容量的路径,
        // 打包必须走 GNU longname(typeflag 'L')而不是让整个证据包失败。
        let dir = crate::unique_test_dir("tar-cjk");
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("evidence.bin");
        let payload = b"dumpalltest tar longname";
        std::fs::write(&source, payload).unwrap();
        let long_segment = "取证证据目录".repeat(12); // 60 汉字 = 180 字节 > 100
        let relative = format!("raw/{long_segment}/恶意文件名超长样本.log");
        let staged = vec![StagedFile {
            absolute: source.clone(),
            relative: relative.clone(),
            size_bytes: payload.len() as u64,
            sha256: {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(payload);
                digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
            },
        }];
        let package = dir.join("pack.tar");
        write_tar_package(&package, &staged).unwrap();
        let data = std::fs::read(&package).unwrap();
        // 第一个头必须是 longname 伪条目。
        assert_eq!(data[156], b'L');
        let size_field = std::str::from_utf8(&data[124..136]).unwrap();
        let size = u64::from_str_radix(size_field.trim_matches('\0').trim(), 8).unwrap();
        let embedded = String::from_utf8_lossy(&data[512..512 + size as usize - 1]).to_string();
        assert_eq!(embedded, relative);
        // longname 之后紧跟真实条目(typeflag '0')。
        let long_blocks = ((size as usize + 511) / 512) * 512;
        assert_eq!(data[512 + long_blocks + 156], b'0');
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use crate::output::paths::OutputLayout;

    fn stage_for_test(absolute: &Path, relative: &str) -> StagedFile {
        StagedFile {
            absolute: absolute.to_path_buf(),
            relative: relative.to_string(),
            size_bytes: fs::metadata(absolute).unwrap().len(),
            sha256: sha256_file_hex(absolute).unwrap(),
        }
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        crate::unique_test_dir(prefix)
    }

    #[test]
    fn zip_pack_aborts_when_source_content_changes_after_staging() {
        let root = unique_dir("dumpall-pack-change");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("a.txt");
        fs::write(&file, b"hello").unwrap();
        let staged = vec![stage_for_test(&file, "a.txt")];
        // 登记后同尺寸替换内容：size 校验过、sha256 校验必须失败。
        fs::write(&file, b"HELLO").unwrap();
        let package = root.join("out.zip");
        let error = write_zip_package(&package, &staged).unwrap_err();
        assert!(error.to_string().contains("sha256 mismatch"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tar_pack_aborts_when_source_size_changes_after_staging() {
        let root = unique_dir("dumpall-pack-size");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("a.txt");
        fs::write(&file, b"hello").unwrap();
        let staged = vec![stage_for_test(&file, "a.txt")];
        // 登记后追加字节：written != 登记尺寸必须报错。
        fs::write(&file, b"hello!!!").unwrap();
        let package = root.join("out.tar");
        let error = write_tar_package(&package, &staged).unwrap_err();
        assert!(error.to_string().contains("size mismatch"));
        let _ = fs::remove_dir_all(root);
    }

    /// 手工解析 ZIP：EOCD → 中央目录 → 本地头 → stored 数据，验证结构、CRC 与内容。
    #[test]
    fn zip_package_round_trip_verifies_structure_crc_and_dos_time() {
        let root = unique_dir("dumpall-pack-zip-rt");
        fs::create_dir_all(&root).unwrap();
        let first = root.join("manifest.json");
        let second = root.join("reports");
        fs::create_dir_all(&second).unwrap();
        let second = second.join("report.md");
        fs::write(&first, b"{\"tool\":\"dumpall\"}").unwrap();
        fs::write(&second, b"line1\nline2\n").unwrap();
        let staged = vec![
            stage_for_test(&first, "manifest.json"),
            stage_for_test(&second, "reports/report.md"),
        ];
        let package = root.join("out.zip");
        let streamed = write_zip_package(&package, &staged).unwrap();
        assert_eq!(streamed.len(), 2);

        let data = fs::read(&package).unwrap();
        // EOCD：从尾部回扫签名。
        let eocd = data
            .windows(4)
            .rev()
            .position(|window| window == 0x0605_4b50u32.to_le_bytes())
            .map(|offset| data.len() - offset - 4)
            .expect("EOCD signature");
        assert_eq!(u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]), 2);
        let central_offset =
            u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;

        let mut cursor = central_offset;
        let mut seen: Vec<(String, Vec<u8>, u32)> = Vec::new();
        while cursor + 4 <= data.len() && data[cursor..cursor + 4] == 0x0201_4b50u32.to_le_bytes() {
            let name_len =
                u16::from_le_bytes(data[cursor + 28..cursor + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(data[cursor + 30..cursor + 32].try_into().unwrap()) as usize;
            let local_offset =
                u32::from_le_bytes(data[cursor + 42..cursor + 46].try_into().unwrap()) as usize;
            let name =
                String::from_utf8(data[cursor + 46..cursor + 46 + name_len].to_vec()).unwrap();

            let local = local_offset;
            assert_eq!(data[local..local + 4], 0x0403_4b50u32.to_le_bytes());
            let local_crc =
                u32::from_le_bytes(data[local + 14..local + 18].try_into().unwrap());
            let local_name_len =
                u16::from_le_bytes(data[local + 26..local + 28].try_into().unwrap()) as usize;
            let local_extra_len =
                u16::from_le_bytes(data[local + 28..local + 30].try_into().unwrap()) as usize;
            let data_start = local + 30 + local_name_len + local_extra_len;
            let size =
                u32::from_le_bytes(data[local + 22..local + 26].try_into().unwrap()) as usize;
            let content = data[data_start..data_start + size].to_vec();

            let mut crc = Crc32Hasher::new();
            crc.update(&content);
            assert_eq!(crc.finalize(), local_crc, "crc mismatch for {name}");
            // 本地头 DOS 日期不得为 0（当年在 1980..=2107 内）。
            let dos_date =
                u16::from_le_bytes(data[local + 12..local + 14].try_into().unwrap());
            assert_ne!(0, dos_date, "dos date must reflect current date");

            seen.push((name, content, local_crc));
            cursor += 46 + name_len + extra_len;
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "manifest.json");
        assert_eq!(seen[0].1, b"{\"tool\":\"dumpall\"}".to_vec());
        assert_eq!(seen[1].0, "reports/report.md");
        assert_eq!(seen[1].1, b"line1\nline2\n".to_vec());
        let _ = fs::remove_dir_all(root);
    }

    /// 手工解析 TAR：512 字节头、校验和、内容与 padding。
    #[test]
    fn tar_package_round_trip_verifies_headers_and_padding() {
        let root = unique_dir("dumpall-pack-tar-rt");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("evidence.bin");
        let content = b"abc".to_vec();
        fs::write(&file, &content).unwrap();
        let staged = vec![stage_for_test(&file, "evidence/evidence.bin")];
        let package = root.join("out.tar");
        write_tar_package(&package, &staged).unwrap();

        let data = fs::read(&package).unwrap();
        assert!(data.len() >= 512 + 512 + 1024);
        let header = &data[..512];
        let expected_name = b"evidence/evidence.bin";
        assert_eq!(&header[..expected_name.len()], expected_name);
        assert_eq!(header[expected_name.len()], 0);
        let stored_size = u64::from_str_radix(
            std::str::from_utf8(&header[124..136])
                .unwrap()
                .trim_end_matches(char::from(0))
                .trim(),
            8,
        )
        .unwrap();
        assert_eq!(stored_size, 3);
        // 校验和：头部 148..156 视为空格后求和。
        let mut checksum_bytes = header.to_vec();
        checksum_bytes[148..156].fill(b' ');
        let checksum: u32 = checksum_bytes.iter().map(|byte| *byte as u32).sum();
        let stored = std::str::from_utf8(&header[148..154]).unwrap();
        assert_eq!(format!("{checksum:06o}"), stored);
        assert_eq!(&data[512..515], &content[..]);
        assert!(data[515..512 + 512].iter().all(|byte| *byte == 0));
        // 结尾 1024 字节全 0。
        assert!(data[data.len() - 1024..].iter().all(|byte| *byte == 0));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pack_failure_records_row_in_collection_errors() {
        let root = unique_dir("dumpall-pack-failure-log");
        let layout = OutputLayout::from_root(root.clone());
        fs::create_dir_all(&layout.collection_dir).unwrap();
        record_pack_failure(
            &layout,
            &DumpallError::Message("evidence-pack source changed while packing".to_string()),
        );
        record_pack_failure(
            &layout,
            &DumpallError::Message("second failure".to_string()),
        );
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_path(&layout.collection_errors)
            .unwrap();
        let records: Vec<csv::StringRecord> = reader.records().flatten().collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].get(0), Some("timestamp"));
        assert_eq!(records[1].get(1), Some("evidence_pack"));
        assert_eq!(records[2].get(1), Some("evidence_pack"));
        assert!(records[2].get(5).unwrap().contains("second failure"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dos_date_time_now_encodes_current_local_time() {
        let (dos_time, dos_date) = dos_date_time_now();
        let year = 1980 + (dos_date >> 9) as i32;
        let now_year = crate::time_utils::now().year();
        assert_eq!(year, now_year);
        assert!(dos_time > 0 || dos_date > 0);
    }

    #[test]
    fn tar_octal_writer_keeps_trailing_nul() {
        let mut target = [0u8; 8];
        write_octal(&mut target, 0o644);
        assert_eq!(&target[..7], b"0000644");
        assert_eq!(target[7], 0);
    }

    #[test]
    fn pack_candidates_do_not_include_raw_http_events() {
        let layout = OutputLayout::from_root(PathBuf::from("results_test"));
        let relatives = pack_candidates(&layout, false)
            .into_iter()
            .map(|candidate| candidate.relative)
            .collect::<Vec<_>>();
        assert!(relatives.iter().any(|value| value == "reports/report.html"));
        assert!(relatives
            .iter()
            .any(|value| value == "reports/summary_report.md"));
        assert!(!relatives
            .iter()
            .any(|value| value == "collection/http_events.jsonl"));
    }

    #[test]
    fn triage_pack_includes_raw_but_not_full_memory_sidecars() {
        let root = std::env::temp_dir().join(format!("dumpall-pack-{}", std::process::id()));
        let layout = OutputLayout::from_root(root.clone());
        std::fs::create_dir_all(layout.raw_dir.join("memory_dumps")).unwrap();
        std::fs::write(layout.raw_dir.join("auth.log"), b"event").unwrap();
        std::fs::create_dir_all(layout.raw_dir.join("etc")).unwrap();
        std::fs::write(layout.raw_dir.join("etc/shadow"), b"secret").unwrap();
        std::fs::write(layout.raw_dir.join("memory.bin"), b"ram").unwrap();
        std::fs::write(layout.raw_dir.join("memory_dumps/1.dmp"), b"dump").unwrap();
        let relatives = pack_candidates(&layout, true)
            .into_iter()
            .map(|candidate| candidate.relative)
            .collect::<Vec<_>>();
        assert!(relatives.iter().any(|value| value == "raw/auth.log"));
        assert!(!relatives.iter().any(|value| value == "raw/etc/shadow"));
        assert!(!relatives.iter().any(|value| value == "raw/memory.bin"));
        assert!(!relatives
            .iter()
            .any(|value| value == "raw/memory_dumps/1.dmp"));
        let _ = std::fs::remove_dir_all(root);
    }
}
