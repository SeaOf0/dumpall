use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::error::{DumpallError, Result};
use crate::model::{
    AppLogEvent, CollectionError, ContainerLogEvent, DbLogEvent, EvidenceGap, Finding,
    HttpLogEvent, LinuxEvent, ParseError, WafLogEvent, WindowsEvent,
};
use crate::output::paths::OutputLayout;

pub struct RunLogger {
    file: File,
    verbose: bool,
}

impl RunLogger {
    pub fn create(path: &Path, verbose: bool) -> Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, verbose })
    }

    pub fn log(&mut self, message: impl AsRef<str>) -> Result<()> {
        let line = format!("{} {}\n", crate::time_utils::now_iso(), message.as_ref());
        self.file.write_all(line.as_bytes())?;
        if self.verbose {
            eprint!("{line}");
        }
        Ok(())
    }
}

pub fn initialize_required_files(layout: &OutputLayout) -> Result<()> {
    fs::write(&layout.run_log, "")?;
    fs::write(&layout.system_info, "{}\n")?;
    write_text(
        &layout.middleware,
        "kind,source,evidence,confidence,notes\n",
    )?;
    write_text(
        &layout.processes,
        "pid,ppid,name,executable_path,command_line,started_at,user,is_web_related\n",
    )?;
    write_text(&layout.process_tree, "")?;
    write_text(
        &layout.network_connections,
        "protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,remote_class\n",
    )?;
    write_text(
        &layout.users,
        "name,enabled,uid_or_sid,description,last_logon,source\n",
    )?;
    write_text(&layout.privileged_users, "name,group,uid_or_sid,source\n")?;
    write_text(&layout.logons, "user,terminal,source,logon_time,detail\n")?;
    write_text(
        &layout.scheduled_tasks,
        "name,path,state,command,user,source\n",
    )?;
    write_text(&layout.startup_items, "name,command,location,user,source\n")?;
    write_text(
        &layout.services,
        "name,display_name,state,start_mode,path,user,source\n",
    )?;
    write_text(
        &layout.web_roots,
        "path,source,middleware,priority,exists,readable,notes,evidence\n",
    )?;
    write_text(
        &layout.discovered_logs,
        "path,source,middleware,priority,exists,notes,evidence\n",
    )?;
    write_text(
        &layout.discovered_db_logs,
        "path,source,db_type,priority,exists,notes,evidence\n",
    )?;
    write_text(
        &layout.discovered_app_logs,
        "path,source,framework,priority,exists,notes,evidence\n",
    )?;
    write_text(
        &layout.discovered_waf_logs,
        "path,source,vendor,priority,exists,notes,evidence\n",
    )?;
    write_http_events_jsonl(&layout.http_events, &[])?;
    write_db_events_jsonl(&layout.db_events, &[])?;
    write_app_events_jsonl(&layout.app_events, &[])?;
    write_waf_events_jsonl(&layout.waf_events, &[])?;
    write_collection_errors(&layout.collection_errors, &[])?;
    write_parse_errors(&layout.parse_errors, &[])?;
    write_findings_jsonl(&layout.findings_jsonl, &[])?;
    write_findings_csv(&layout.findings_csv, &[])?;
    write_text(
        &layout.high_risk_events,
        "finding_id,severity,confidence,evidence_quality,score,category,rule_id,timestamp,remote_ip,uri_path,source_file,line_number,related_ids,evidence_chain_level,evidence_chain,recommendation\n",
    )?;
    write_text(
        &layout.attack_ip_stats,
        "remote_ip,findings,total_score,max_score,highest_severity,categories,top_paths,first_seen,last_seen\n",
    )?;
    write_text(
        &layout.attack_type_stats,
        "category,findings,high_or_critical,max_score,highest_severity,affected_ips,affected_paths\n",
    )?;
    write_text(
        &layout.recent_web_files,
        "path,root_path,size_bytes,modified_at,extension,high_risk_extension,double_extension,reason\n",
    )?;
    write_text(
        &layout.suspicious_files,
        "path,root_path,size_bytes,modified_at,extension,high_risk_extension,double_extension,reason\n",
    )?;
    write_text(
        &layout.suspicious_processes,
        "pid,ppid,name,reason,source\n",
    )?;
    write_text(
        &layout.suspicious_network,
        "protocol,local_address,local_port,remote_address,remote_port,state,pid,reason,source\n",
    )?;
    write_text(
        &layout.suspicious_db_events,
        "finding_id,timestamp,severity,score,category,rule_id,db_type,db_user,db_name,client_ip,statement_type,statement_summary,source_file,line_number,raw_hash,recommendation\n",
    )?;
    write_text(
        &layout.suspicious_app_events,
        "finding_id,timestamp,severity,score,category,rule_id,framework,level,exception_type,http_path,trace_id,request_id,message_summary,source_file,line_number,raw_hash,recommendation\n",
    )?;
    write_text(
        &layout.suspicious_waf_events,
        "finding_id,timestamp,severity,score,category,rule_id,vendor,action,waf_rule_id,waf_rule_name,client_ip,proxy_ip,host,method,path,status,waf_score,source_file,line_number,raw_hash,recommendation\n",
    )?;
    write_evidence_gaps(&layout.evidence_gaps, &[])?;
    write_text(
        &layout.updated_files,
        "path,size_bytes,modified_at,is_executable,tool_hint,reason\n",
    )?;
    write_text(
        &layout.yara_matches,
        "timestamp,file_path,file_sha256,file_size,mtime,rule_namespace,rule_name,rule_tags,match_count,matched_offsets_summary,score_delta,recommendation\n",
    )?;
    write_text(
        &layout.ioc_matches,
        "match_id,timestamp,indicator_type,indicator_value,matched_field,matched_value,source,confidence,tags,description,evidence_source,evidence_line,score_delta,recommendation\n",
    )?;
    write_text(
        &layout.ip_enrichment,
        "ip,ip_type,country,region,city,asn,as_org,is_internal,first_seen,last_seen,request_count,finding_count,max_score,sources,client_ip_source,proxy_ips\n",
    )?;
    write_text(
        &layout.geoip_summary,
        "country,ip_count,request_count,finding_count,max_score\n",
    )?;
    write_text(
        &layout.asn_summary,
        "asn,as_org,ip_count,request_count,finding_count,max_score\n",
    )?;
    write_text(&layout.ioc_sources, "[]\n")?;
    write_text(&layout.rules_manifest, "{}\n")?;
    write_text(
        &layout.effective_allowlist,
        "# No allowlist file was supplied.\n",
    )?;
    write_text(
        &layout.java_components,
        "component_id,runtime_type,component_type,name,class_name,source_file,source_path,declared_in,mtime,sha256,is_recent,is_baseline_new,risk_flags,confidence\n",
    )?;
    write_text(
        &layout.tomcat_components,
        "component_id,runtime_type,component_type,name,class_name,url_pattern,source_file,source_path,declared_in,mtime,sha256,is_recent,is_baseline_new,risk_flags,confidence\n",
    )?;
    write_text(
        &layout.spring_mappings,
        "component_id,component_type,route,http_method,class_name,jar_path,source,is_from_actuator,is_from_log,is_from_static_archive,mtime,sha256,risk_flags,confidence\n",
    )?;
    write_text(
        &layout.iis_modules,
        "component_id,site_name,app_pool,component_type,name,path,precondition,source_config,mtime,sha256,signature_status,is_recent,is_baseline_new,risk_flags,confidence\n",
    )?;
    write_text(
        &layout.aspnet_handlers,
        "component_id,site_name,app_pool,component_type,name,path,verb,resource_type,source_config,mtime,sha256,risk_flags,confidence\n",
    )?;
    write_text(
        &layout.runtime_warnings,
        "timestamp,target,path,message,evidence_gap,detail\n",
    )?;
    write_text(
        &layout.component_diff,
        "component_id,component_type,name,path,change_type,baseline_path,current_hash,baseline_hash,risk_flags\n",
    )?;
    write_text(&layout.windows_events, "")?;
    write_text(&layout.linux_events, "")?;
    write_text(
        &layout.auth_events,
        "event_id,timestamp,source,user,source_ip,target_user,result,raw_hash,parser_confidence\n",
    )?;
    write_text(
        &layout.process_events,
        "event_id,timestamp,source,process_name,process_id,parent_process_name,command_line_summary,user,raw_hash,parser_confidence\n",
    )?;
    write_text(
        &layout.service_events,
        "event_id,timestamp,source,service_name,action,path,user,raw_hash,parser_confidence\n",
    )?;
    write_text(
        &layout.scheduled_task_events,
        "event_id,timestamp,source,task_name,action,command,user,raw_hash,parser_confidence\n",
    )?;
    write_text(
        &layout.powershell_events,
        "event_id,timestamp,source,script_summary,user,process_id,raw_hash,parser_confidence\n",
    )?;
    write_text(
        &layout.event_parse_errors,
        "source_file,line_number,parser_name,message,raw_hash,raw_sample\n",
    )?;
    write_text(
        &layout.containers,
        "container_id,container_name,image,image_id,pod_name,namespace,process_id,created_at,started_at,is_privileged,host_pid,host_network,risk_flags\n",
    )?;
    write_text(
        &layout.images,
        "image,image_id,created_at,size,repo_tags,digest\n",
    )?;
    write_text(
        &layout.mounts,
        "container_id,container_name,source,destination,mode,is_sensitive,risk_flags\n",
    )?;
    write_text(
        &layout.container_network,
        "container_id,container_name,network,ip_address,ports,host_network,risk_flags\n",
    )?;
    write_text(&layout.container_logs, "")?;
    write_text(
        &layout.container_findings,
        "finding_id,timestamp,severity,score,category,container_id,container_name,rule_id,evidence_summary,recommendation\n",
    )?;
    write_text(&layout.pack_manifest, "{}\n")?;
    write_text(&layout.pack_hashes, "path,sha256,size_bytes\n")?;
    write_text(
        &layout.evidence_index_csv,
        "path,kind,description,source,required,sha256,size_bytes\n",
    )?;
    write_text(&layout.evidence_index_json, "[]\n")?;
    write_text(
        &layout.review_guide,
        "# 证据包复核指南\n\n本次运行未启用证据包生成。\n",
    )?;
    write_text(
        &layout.file_hashes,
        "path,root_path,size_bytes,modified_at,sha256,magic_type,extension,scanned_by\n",
    )?;
    write_text(
        &layout.evidence_copy_manifest,
        "source_path,relative_path,size_bytes,sha256,mtime,reason,status\n",
    )?;
    write_text(
        &layout.html_report,
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>dumpall 报告</title></head><body><h1>dumpall 报告</h1><p>报告生成尚未完成。</p></body></html>\n",
    )?;
    write_text(
        &layout.runtime_report,
        "# 运行时组件报告\n\n运行时组件采集未启用，或未输出发现项。\n",
    )?;
    write_text(
        &layout.host_events_report,
        "# 主机事件报告\n\n主机事件采集未启用，或未输出发现项。\n",
    )?;
    write_text(
        &layout.container_report,
        "# 容器证据报告\n\n容器采集未启用，或未输出发现项。\n",
    )?;
    Ok(())
}

/// 同目录临时文件路径（.tmp 后缀）：用于"临时文件 + rename"的原子写。
fn sibling_temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

/// 原子写 JSON：先写同目录 .tmp 再 rename，避免读者看到半截文件；
/// 任何失败按原错误传播（失败时清理临时文件）。
pub fn write_json_pretty<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let temp = sibling_temp_path(path);
    let write_result = (|| -> Result<()> {
        let file = File::create(&temp)?;
        serde_json::to_writer_pretty(file, value)?;
        Ok(())
    })();
    match write_result {
        Ok(()) => fs::rename(&temp, path).map_err(|error| {
            let _ = fs::remove_file(&temp);
            DumpallError::from(error)
        }),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error)
        }
    }
}

/// 原子写文本：先写同目录 .tmp 再 rename；失败按原错误传播。
pub fn write_text(path: &Path, content: &str) -> Result<()> {
    let temp = sibling_temp_path(path);
    match fs::write(&temp, content) {
        Ok(()) => fs::rename(&temp, path).map_err(|error| {
            let _ = fs::remove_file(&temp);
            DumpallError::from(error)
        }),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(DumpallError::from(error))
        }
    }
}

pub fn write_csv_serialize<T: serde::Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    for row in rows {
        writer.serialize(row)?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_collection_errors(path: &Path, rows: &[CollectionError]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "timestamp",
        "source",
        "path",
        "operation",
        "message",
        "detail",
    ])?;
    for row in rows {
        // path/message/detail 可能携带被检主机文件名或原文片段，统一公式注入防护。
        writer.write_record([
            row.timestamp.as_str(),
            row.source.as_str(),
            &csv_safe_cell(row.path.as_str()),
            row.operation.as_str(),
            &csv_safe_cell(row.message.as_str()),
            &csv_safe_cell(row.detail.as_deref().unwrap_or_default()),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_parse_errors(path: &Path, rows: &[ParseError]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "source_file",
        "line_number",
        "parser_name",
        "message",
        "raw_hash",
        "raw_sample",
    ])?;
    for row in rows {
        // source_file 来自文件系统路径，raw_sample 来自日志原文：均为攻击者可控内容。
        writer.write_record([
            &csv_safe_cell(row.source_file.as_str()),
            &row.line_number.to_string(),
            row.parser_name.as_str(),
            &csv_safe_cell(row.message.as_str()),
            row.raw_hash.as_str(),
            &csv_safe_cell(row.raw_sample.as_deref().unwrap_or_default()),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_findings_jsonl(path: &Path, rows: &[Finding]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_http_events_jsonl(path: &Path, rows: &[HttpLogEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_db_events_jsonl(path: &Path, rows: &[DbLogEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_app_events_jsonl(path: &Path, rows: &[AppLogEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_waf_events_jsonl(path: &Path, rows: &[WafLogEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_windows_events_jsonl(path: &Path, rows: &[WindowsEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_linux_events_jsonl(path: &Path, rows: &[LinuxEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_container_logs_jsonl(path: &Path, rows: &[ContainerLogEvent]) -> Result<()> {
    let mut file = File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

/// CSV 公式注入防护：单元格以 = + - @ TAB CR 开头时前置单引号，
/// 防止分析师用 Excel/WPS 打开 findings.csv 等报告时执行攻击者植入在日志
/// URL/UA/证据摘要里的公式（HYPERLINK 外联、DDE）。纯占位符 "-" 不处理。
pub fn csv_safe_cell(value: &str) -> String {
    let mut chars = value.chars();
    if let Some(first) = chars.next() {
        if matches!(first, '=' | '+' | '@' | '\t' | '\r') {
            return format!("'{value}");
        }
        if first == '-' && chars.next().is_some() {
            return format!("'{value}");
        }
    }
    value.to_string()
}

pub fn write_findings_csv(path: &Path, rows: &[Finding]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "finding_id",
        "timestamp",
        "severity",
        "confidence",
        "evidence_quality",
        "evidence_quality_basis",
        "score",
        "category",
        "rule_id",
        "rule_name",
        "source_type",
        "source_file",
        "line_number",
        "remote_ip",
        "method",
        "uri_path",
        "status",
        "evidence_summary",
        "raw_hash",
        "related_ids",
        "evidence_chain_level",
        "evidence_chain_basis",
        "score_breakdown",
        "recommendation",
    ])?;
    for row in rows {
        // 攻击者可控字段（来自被检主机日志原文）统一走公式注入防护。
        writer.write_record([
            row.finding_id.as_str(),
            row.timestamp.as_deref().unwrap_or_default(),
            row.severity.as_str(),
            row.confidence.as_str(),
            row.evidence_quality.as_str(),
            row.evidence_quality_basis.as_str(),
            &row.score.to_string(),
            row.category.as_str(),
            row.rule_id.as_str(),
            &csv_safe_cell(row.rule_name.as_str()),
            row.source_type.as_str(),
            &csv_safe_cell(row.source_file.as_deref().unwrap_or_default()),
            &row.line_number
                .map(|line| line.to_string())
                .unwrap_or_default(),
            &csv_safe_cell(row.remote_ip.as_deref().unwrap_or_default()),
            &csv_safe_cell(row.method.as_deref().unwrap_or_default()),
            &csv_safe_cell(row.uri_path.as_deref().unwrap_or_default()),
            &row.status
                .map(|status| status.to_string())
                .unwrap_or_default(),
            &csv_safe_cell(row.evidence_summary.as_str()),
            row.raw_hash.as_deref().unwrap_or_default(),
            &row.related_ids.join(";"),
            row.evidence_chain_level.as_deref().unwrap_or_default(),
            row.evidence_chain_basis.as_deref().unwrap_or_default(),
            &serde_json::to_string(&row.score_breakdown)?,
            &csv_safe_cell(row.recommendation.as_str()),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn write_evidence_gaps(path: &Path, rows: &[EvidenceGap]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    writer.write_record([
        "gap_id",
        "timestamp",
        "source",
        "path",
        "operation",
        "message",
        "detail",
        "coverage_status",
        "confidence",
        "evidence_quality",
        "recommendation",
    ])?;
    for row in rows {
        // path/message/detail 可能携带被检主机文件名或原文片段，统一公式注入防护。
        writer.write_record([
            row.gap_id.as_str(),
            row.timestamp.as_str(),
            row.source.as_str(),
            &csv_safe_cell(row.path.as_str()),
            row.operation.as_str(),
            &csv_safe_cell(row.message.as_str()),
            &csv_safe_cell(row.detail.as_deref().unwrap_or_default()),
            row.coverage_status.as_str(),
            row.confidence.as_str(),
            row.evidence_quality.as_str(),
            row.recommendation.as_str(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}
