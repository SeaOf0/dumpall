//! 主机横向/场景化聚合检测：基于采集 CSV 的跨行聚合规则。
//!
//! 覆盖场景：
//! - HOST-NET-SCAN-001：本机发起的端口/主机扫描（fscan/nmap/爆破工具的行为特征）——
//!   快照中单个进程连接 ≥10 个不同远端 IP，或对同一 IP 探测 ≥15 个不同端口。
//! - HOST-RANSOM-FILE-001：勒索软件落地痕迹——临时目录/用户目录/Web 目录中
//!   出现勒索信文件名或加密后缀模式。

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::config::ResolvedRun;
use crate::error::Result;
use crate::model::{EvidenceQuality, Finding, ScoreBreakdown, Severity};
use crate::output::paths::OutputLayout;
use crate::output::writers::RunLogger;

#[derive(Debug, Default)]
pub struct HostEnrichmentReport {
    pub findings: Vec<Finding>,
}

pub fn run_host_enrichment_detection(
    resolved: &ResolvedRun,
    layout: &OutputLayout,
    logger: &mut RunLogger,
) -> Result<HostEnrichmentReport> {
    if resolved.mode == crate::model::RunMode::Analyze {
        return Ok(HostEnrichmentReport::default());
    }
    let mut findings = Vec::new();
    findings.extend(scan_fanout_findings(layout, 1)?);
    let next_index = findings.len() + 1;
    findings.extend(ransom_artifact_findings(layout, next_index)?);
    logger.log(format!(
        "detector: host enrichment produced {} finding(s)",
        findings.len()
    ))?;
    Ok(HostEnrichmentReport { findings })
}

/// 连接快照 → (process, remote_ip, remote_port, state) 行。
struct ConnectionRow {
    process_name: String,
    remote_ip: String,
    remote_port: String,
    state: String,
}

/// 本机扫描行为检测：单进程不同远端 IP 数 ≥10，或同 IP 不同端口 ≥15。
/// seq_start 用于生成全局唯一 finding_id（与其它模块的 F-{index} 风格一致）。
fn scan_fanout_findings(layout: &OutputLayout, seq_start: usize) -> Result<Vec<Finding>> {
    const DISTINCT_IP_THRESHOLD: usize = 10;
    const DISTINCT_PORT_THRESHOLD: usize = 15;
    let rows = read_connections(&layout.network_connections);
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut by_process: BTreeMap<String, Vec<&ConnectionRow>> = BTreeMap::new();
    for row in &rows {
        by_process
            .entry(row.process_name.clone())
            .or_default()
            .push(row);
    }
    let mut findings = Vec::new();
    for (process, conns) in by_process {
        let mut ips: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut ports_by_ip: BTreeMap<&str, std::collections::BTreeSet<&str>> = BTreeMap::new();
        for conn in &conns {
            if conn.remote_ip.is_empty() || conn.remote_ip == "unknown" {
                continue;
            }
            // LISTEN 态无远端，不参与扇出统计。
            if conn.state.eq_ignore_ascii_case("listen") {
                continue;
            }
            ips.insert(conn.remote_ip.as_str());
            ports_by_ip
                .entry(conn.remote_ip.as_str())
                .or_default()
                .insert(conn.remote_port.as_str());
        }
        let mut summary = None;
        if ips.len() >= DISTINCT_IP_THRESHOLD {
            summary = Some(format!(
                "process `{process}` has live connections to {} distinct remote address(es) — host/port scanning or lateral movement fan-out (fscan/nmap/brute-force style). Sample targets: {}",
                ips.len(),
                ips.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
            ));
        } else {
            for (ip, ports) in ports_by_ip {
                if ports.len() >= DISTINCT_PORT_THRESHOLD {
                    summary = Some(format!(
                        "process `{process}` probes {} distinct port(s) on {ip} — port scan behavior",
                        ports.len()
                    ));
                    break;
                }
            }
        }
        if let Some(text) = summary {
            let seq = seq_start + findings.len();
            findings.push(build_finding(
                66,
                "lateral_scan",
                "HOST-NET-SCAN-001",
                "Process fans out to many targets (scan or lateral movement)",
                format!("{text}. Treat as scanning evidence for manual review, not proof of compromise."),
                Some(layout.network_connections.display().to_string()),
                seq,
            ));
        }
    }
    Ok(findings)
}

/// 勒索痕迹：对已采集的文件清单做勒索信/加密后缀模式匹配。
/// seq_start 用于生成全局唯一 finding_id。
fn ransom_artifact_findings(layout: &OutputLayout, seq_start: usize) -> Result<Vec<Finding>> {
    const NOTE_PATTERNS: [&str; 12] = [
        "readme_restore",
        "how_to_decrypt",
        "how_to_recover",
        "restore_files",
        "decrypt_instruction",
        "!!!restore!!!",
        "recovery_instructions",
        "すべてのファイル", // 日语勒索信常见前缀
        "_readme.",
        "ransom",
        "restore-",
        "recover_files",
    ];
    const ENCRYPTED_EXTENSIONS: [&str; 10] = [
        ".locked",
        ".encrypted",
        ".crypt",
        ".enc",
        ".lockbit",
        ".phobos",
        ".mkp",
        ".devos",
        ".eking",
        ".moneyistime",
    ];
    let mut findings = Vec::new();
    let mut checked: u64 = 0;
    for csv in [
        &layout.temp_files,
        &layout.user_dirs,
        &layout.recent_web_files,
        &layout.suspicious_files,
    ] {
        let rows = read_csv_paths(csv);
        for path in rows {
            checked += 1;
            let lower = path.to_ascii_lowercase();
            if NOTE_PATTERNS.iter().any(|pattern| lower.contains(pattern)) {
                findings.push(build_finding(
                    80,
                    "ransomware",
                    "HOST-RANSOM-FILE-001",
                    "Ransom note filename pattern",
                    format!("Filename `{path}` matches common ransom-note naming. Verify content and neighboring file extensions manually."),
                    Some(csv.display().to_string()),
                    seq_start + findings.len(),
                ));
                if findings.len() >= 50 {
                    return Ok(findings);
                }
                continue;
            }
            if ENCRYPTED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
                findings.push(build_finding(
                    74,
                    "ransomware",
                    "HOST-RANSOM-FILE-001",
                    "Ransomware-encrypted file extension",
                    format!("File `{path}` carries a known ransomware family extension. Inspect the directory for mass renaming and a note file."),
                    Some(csv.display().to_string()),
                    seq_start + findings.len(),
                ));
                if findings.len() >= 50 {
                    return Ok(findings);
                }
            }
        }
    }
    let _ = checked;
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    score: u16,
    category: &str,
    rule_id: &str,
    rule_name: &str,
    evidence_summary: String,
    source_file: Option<String>,
    seq: usize,
) -> Finding {
    // 评分拆分只在专用字段记一次（host_event_score），不再 from_base 同值双记。
    let mut breakdown = ScoreBreakdown::default();
    breakdown.host_event_score = score as i16;
    Finding {
        // 按序号生成唯一 ID（HE-ENR-F-{seq:04}）；此前用 rule_id 生成导致
        // 多条发现共用同一 ID，无法在 findings 输出中区分。
        finding_id: format!("HE-ENR-F-{seq:04}"),
        timestamp: Some(crate::time_utils::now_iso()),
        severity: Severity::from_score(score),
        score,
        confidence: crate::model::confidence_for(score, EvidenceQuality::Q2),
        evidence_quality: EvidenceQuality::Q2,
        evidence_quality_basis: "Q2 aggregated host inventory evidence".to_string(),
        score_breakdown: breakdown,
        category: category.to_string(),
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        source_type: "host_inventory".to_string(),
        source_file,
        line_number: None,
        remote_ip: None,
        method: None,
        uri_path: None,
        status: None,
        evidence_summary,
        raw_hash: None,
        related_ids: Vec::new(),
        recommendation: "Corroborate with process tree, network timeline, and file inventory; verify before containment.".to_string(),
        evidence_chain_level: None,
        evidence_chain_basis: None,
    }
}

fn read_connections(path: &Path) -> Vec<ConnectionRow> {
    // 兼容旧版 remote_ip，同时接受采集器当前使用的 remote_address。
    let mut rows = Vec::new();
    let Ok(file) = File::open(path) else {
        return rows;
    };
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(BufReader::new(file));
    let headers = match reader.headers() {
        Ok(headers) => headers.clone(),
        Err(_) => return rows,
    };
    let index_of = |name: &str| headers.iter().position(|h| h == name);
    let Some(ip_idx) = index_of("remote_address").or_else(|| index_of("remote_ip")) else {
        return rows;
    };
    let (Some(port_idx), Some(state_idx), Some(proc_idx)) = (
        index_of("remote_port"),
        index_of("state"),
        index_of("process_name"),
    ) else {
        return rows;
    };
    for record in reader.records().flatten() {
        let field = |idx: usize| record.get(idx).unwrap_or_default().to_string();
        rows.push(ConnectionRow {
            process_name: field(proc_idx),
            remote_ip: field(ip_idx),
            remote_port: field(port_idx),
            state: field(state_idx),
        });
    }
    rows
}

fn read_csv_paths(path: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let Ok(file) = File::open(path) else {
        return paths;
    };
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(BufReader::new(file));
    let headers = match reader.headers() {
        Ok(headers) => headers.clone(),
        Err(_) => return paths,
    };
    let Some(path_idx) = headers.iter().position(|h| h == "path") else {
        return paths;
    };
    for record in reader.records().flatten() {
        if let Some(value) = record.get(path_idx) {
            if !value.trim().is_empty() {
                paths.push(value.to_string());
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_aggregation_triggers_on_many_targets() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-fanout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_millis()
        ));
        let collection = dir.join("collection");
        std::fs::create_dir_all(&collection).unwrap();
        let mut csv =
            String::from("local_ip,local_port,remote_ip,remote_port,state,process_name\n");
        for host in 1..=12 {
            csv.push_str(&format!(
                "10.0.0.5,40000,192.168.1.{host},445,established,fscan.exe\n"
            ));
        }
        csv.push_str("10.0.0.5,40001,8.8.8.8,53,established,svchost\n");
        std::fs::write(collection.join("network_connections.csv"), csv).unwrap();
        let layout = OutputLayout::from_root(dir.clone());
        let findings = scan_fanout_findings(&layout, 1).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HOST-NET-SCAN-001");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fanout_accepts_current_network_schema() {
        let dir =
            std::env::temp_dir().join(format!("dumpall-fanout-schema-{}", std::process::id()));
        let collection = dir.join("collection");
        std::fs::create_dir_all(&collection).unwrap();
        let mut csv = String::from("protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,remote_class\n");
        for host in 1..=10 {
            csv.push_str(&format!(
                "tcp,10.0.0.5,40000,192.168.1.{host},445,established,1,fscan,private\n"
            ));
        }
        std::fs::write(collection.join("network_connections.csv"), csv).unwrap();
        let layout = OutputLayout::from_root(dir.clone());
        let findings = scan_fanout_findings(&layout, 1).unwrap();
        assert_eq!(findings.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ransom_extension_matched_in_inventory() {
        let dir = std::env::temp_dir().join(format!(
            "dumpall-ransom-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let findings_dir = dir.join("findings");
        std::fs::create_dir_all(&findings_dir).unwrap();
        std::fs::write(
            findings_dir.join("recent_web_files.csv"),
            "path,root_path,size_bytes,modified_at,extension,high_risk_extension,double_extension\n/data/www/index.php.lockbit,/data/www,1024,2026,x,false,false\n",
        )
        .unwrap();
        let layout = OutputLayout::from_root(dir.clone());
        let findings = ransom_artifact_findings(&layout, 1).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "HOST-RANSOM-FILE-001"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Fix：finding_id 必须按序号唯一（此前 50 条同 ID）。
    #[test]
    fn finding_ids_are_unique_across_rules() {
        // 勒索信 + 加密后缀 + 扫描扇出各产生发现时，ID 不重复。
        let dir = std::env::temp_dir().join(format!(
            "dumpall-enr-uniq-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let collection = dir.join("collection");
        let findings_dir = dir.join("findings");
        std::fs::create_dir_all(&collection).unwrap();
        std::fs::create_dir_all(&findings_dir).unwrap();
        let mut csv =
            String::from("local_ip,local_port,remote_ip,remote_port,state,process_name\n");
        for host in 1..=12 {
            csv.push_str(&format!(
                "10.0.0.5,40000,192.168.1.{host},445,established,fscan.exe\n"
            ));
        }
        std::fs::write(collection.join("network_connections.csv"), csv).unwrap();
        std::fs::write(
            findings_dir.join("recent_web_files.csv"),
            "path,root_path,size_bytes,modified_at,extension,high_risk_extension,double_extension\n/data/www/readme_restore.txt,/data/www,1024,2026,x,false,false\n/data/www/index.php.lockbit,/data/www,1024,2026,x,false,false\n",
        )
        .unwrap();

        let mut findings = Vec::new();
        findings.extend(scan_fanout_findings(&OutputLayout::from_root(dir.clone()), 1).unwrap());
        let next = findings.len() + 1;
        findings.extend(ransom_artifact_findings(&OutputLayout::from_root(dir.clone()), next).unwrap());

        assert!(findings.len() >= 3, "scan + 2 ransom findings");
        let mut ids = findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "finding ids must be unique: {ids:?}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
