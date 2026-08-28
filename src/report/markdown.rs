use std::path::Path;

use crate::correlation::CorrelationReport;
use crate::error::Result;
use crate::model::{CollectionError, EvidenceGap, Finding, RunSummary};
use crate::output::writers;
use crate::report::zh;

pub fn write_summary_report(
    path: &Path,
    summary: &RunSummary,
    findings: &[Finding],
    collection_errors: &[CollectionError],
    evidence_gaps: &[EvidenceGap],
    correlation: &CorrelationReport,
) -> Result<()> {
    writers::write_text(
        path,
        &render_summary_report(
            summary,
            findings,
            collection_errors,
            evidence_gaps,
            correlation,
        ),
    )
}

pub fn render_summary_report(
    summary: &RunSummary,
    findings: &[Finding],
    collection_errors: &[CollectionError],
    evidence_gaps: &[EvidenceGap],
    correlation: &CorrelationReport,
) -> String {
    let mut report = String::new();
    report.push_str("# dumpall 应急排查摘要报告\n\n");
    report.push_str("## 执行摘要\n\n");
    report.push_str(&format!("- 工具版本：{}\n", summary.tool_version));
    report.push_str(&format!("- 执行命令：{}\n", summary.command));
    report.push_str(&format!("- 开始时间：{}\n", summary.started_at));
    report.push_str(&format!("- 结束时间：{}\n", summary.finished_at));
    report.push_str(&format!("- 输出目录：{}\n", summary.output_dir));
    report.push_str(&format!(
        "- 离线模式：{}\n",
        zh::bool_label(summary.offline)
    ));
    report.push_str(&format!("- 脱敏：{}\n", zh::bool_label(summary.redact)));
    report.push_str(&format!(
        "- 权限状态：{}\n",
        zh::placeholder_label(&summary.privilege)
    ));
    report.push_str(&format!("- 输出格式：{}\n", summary.formats.join(", ")));
    report.push('\n');

    report.push_str("## 时间范围\n\n");
    report.push_str(&format!(
        "- 模式：{}\n",
        zh::time_range_mode_label(&summary.time_range.mode)
    ));
    report.push_str(&format!(
        "- 起始：{}\n",
        zh::placeholder_label(summary.time_range.since.as_deref().unwrap_or("not limited"))
    ));
    report.push_str(&format!(
        "- 结束：{}\n",
        zh::placeholder_label(summary.time_range.until.as_deref().unwrap_or("not limited"))
    ));
    report.push('\n');

    report.push_str("## 高危发现\n\n");
    if correlation.high_risk_events.is_empty() {
        if findings.is_empty() {
            report.push_str("本次运行未产生发现项。\n\n");
        } else {
            report.push_str(&format!(
                "本次运行产生 {} 条发现，但没有达到高危或严重级别。\n\n",
                findings.len()
            ));
        }
    } else {
        for event in correlation.high_risk_events.iter().take(20) {
            report.push_str(&format!(
                "- [{}] {}：{}（{}，分数 {}，置信度 {}，证据质量 {}，来源 {}，关联 {}）\n",
                zh::severity_label(&event.severity),
                event.rule_id,
                zh::finding_title(&event.rule_id),
                zh::category_label(&event.category),
                event.score,
                zh::confidence_label(&event.confidence),
                zh::evidence_quality_label(&event.evidence_quality),
                display_or(&event.remote_ip, "无数据"),
                display_or(&event.related_ids, "无")
            ));
            report.push_str(&format!("  证据链：{}。\n", event.evidence_chain_level));
        }
        report.push('\n');
    }

    report.push_str("## 证据质量摘要\n\n");
    let high_or_critical = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.severity,
                crate::model::Severity::High | crate::model::Severity::Critical
            )
        })
        .count();
    report.push_str(&format!(
        "- 带证据质量标记的高危/严重发现：{}\n",
        high_or_critical
    ));
    for quality in ["Q1", "Q2", "Q3", "Q4", "Q5"] {
        let count = findings
            .iter()
            .filter(|finding| finding.evidence_quality.as_str() == quality)
            .count();
        report.push_str(&format!(
            "- {}：{}\n",
            zh::evidence_quality_label(quality),
            count
        ));
    }
    report.push_str(
        "- 查看 `findings/findings.csv` 和 `findings/high_risk_events.csv` 可复核证据质量依据和评分拆分。\n\n",
    );

    report.push_str("## 证据链\n\n");
    if correlation.attack_chains.is_empty() {
        report.push_str("未形成多证据链。\n\n");
    } else {
        for chain in correlation.attack_chains.iter().take(10) {
            report.push_str(&format!(
                "- {} {}：最高分 {}，发现 {}，来源 {}，路径 {}\n",
                chain.chain_id,
                chain.evidence_chain_level,
                chain.max_score,
                chain.finding_ids.join(";"),
                display_or(&chain.remote_ips, "无数据"),
                display_or(&chain.paths, "无数据")
            ));
        }
        report.push_str("\n完整链路细节见 `timeline/attack_chains.md`。\n\n");
    }

    report.push_str("## 攻击来源 IP\n\n");
    if correlation.attack_ip_stats.is_empty() {
        report.push_str("未产生来源 IP 统计。\n\n");
    } else {
        for row in correlation.attack_ip_stats.iter().take(10) {
            report.push_str(&format!(
                "- {}：{} 条发现，最高分 {}，类型 {}，路径 {}\n",
                row.remote_ip,
                row.findings,
                row.max_score,
                zh::category_label(&row.categories),
                display_or(&row.top_paths, "无数据")
            ));
        }
        report.push('\n');
    }

    report.push_str("## 攻击类型\n\n");
    if correlation.attack_type_stats.is_empty() {
        report.push_str("未产生攻击类型统计。\n\n");
    } else {
        for row in correlation.attack_type_stats.iter().take(10) {
            report.push_str(&format!(
                "- {}：{} 条发现，{} 条高危/严重，最高分 {}，IP {}\n",
                zh::category_label(&row.category),
                row.findings,
                row.high_or_critical,
                row.max_score,
                display_or(&row.affected_ips, "无数据")
            ));
        }
        report.push('\n');
    }

    report.push_str("## 受影响 URL\n\n");
    if correlation.affected_url_stats.is_empty() {
        report.push_str("未产生受影响 URL 统计。\n\n");
    } else {
        for row in correlation.affected_url_stats.iter().take(10) {
            report.push_str(&format!(
                "- {}：{} 条发现，最高分 {}，类型 {}，IP {}\n",
                row.uri_path,
                row.findings,
                row.max_score,
                zh::category_label(&row.categories),
                display_or(&row.remote_ips, "无数据")
            ));
        }
        report.push('\n');
    }

    report.push_str("## 可疑主机上下文\n\n");
    push_finding_group(&mut report, "进程", &correlation.suspicious_processes);
    push_finding_group(&mut report, "网络连接", &correlation.suspicious_network);
    push_finding_group(&mut report, "持久化", &correlation.suspicious_persistence);

    report.push_str("## WAF 与应用证据\n\n");
    push_finding_group(&mut report, "WAF/CDN", &correlation.suspicious_waf_events);
    push_finding_group(&mut report, "应用日志", &correlation.suspicious_app_events);

    report.push_str("## 近期 Web 文件变更\n\n");
    if correlation.recent_web_files.is_empty() {
        report.push_str("未采集到近期 Web 文件变更。\n\n");
    } else {
        for row in correlation.recent_web_files.iter().take(10) {
            report.push_str(&format!(
                "- {} 于 {}（{}）\n",
                row.get("path").unwrap_or("无数据"),
                row.get("modified_at").unwrap_or("无数据"),
                zh::message_label(row.get("reason").unwrap_or("recent_change"))
            ));
        }
        report.push('\n');
    }

    report.push_str("## 可疑 Web 文件\n\n");
    if correlation.suspicious_files.is_empty() {
        report.push_str("未采集到可疑 Web 文件元数据。\n\n");
    } else {
        for row in correlation.suspicious_files.iter().take(10) {
            report.push_str(&format!(
                "- {} ({})\n",
                row.get("path").unwrap_or("无数据"),
                zh::message_label(row.get("reason").unwrap_or("suspicious_file"))
            ));
        }
        report.push('\n');
    }

    report.push_str("## 采集健康\n\n");
    report.push_str(&format!("- 扫描文件数：{}\n", summary.files_scanned));
    report.push_str(&format!("- 解析行数：{}\n", summary.lines_parsed));
    report.push_str(&format!("- 采集错误数：{}\n", collection_errors.len()));
    report.push_str(&format!("- 解析错误数：{}\n", summary.parse_errors));
    report.push_str(&format!("- 证据缺口数：{}\n", evidence_gaps.len()));
    report.push('\n');

    report.push_str("## 证据缺口\n\n");
    if evidence_gaps.is_empty() {
        report.push_str("未从采集失败中提升出证据缺口。\n\n");
    } else {
        report.push_str(
            "以下缺口表示：缺少匹配证据不能被解读为该来源干净，只能说明本次运行没有完整覆盖。\n\n",
        );
        // not_collected（完全未覆盖）优先于 partial（部分覆盖），避免平台噪声
        // 缺口把高优先级缺口挤出 top-10 截断；稳定排序保持同级别内原有顺序。
        let mut ordered_gaps: Vec<&crate::model::EvidenceGap> = evidence_gaps.iter().collect();
        ordered_gaps.sort_by_key(|gap| {
            !matches!(
                gap.coverage_status,
                crate::model::CollectionCoverageStatus::NotCollected
            )
        });
        for gap in ordered_gaps.iter().take(10) {
            report.push_str(&format!(
                "- {} 对 {} 执行 {}：{}（{}，{}）\n",
                zh::source_label(&gap.source),
                display_or(&gap.path, "未指定路径"),
                zh::operation_label(&gap.operation),
                zh::message_label(&gap.message),
                zh::coverage_status_label(gap.coverage_status.as_str()),
                zh::evidence_quality_label(gap.evidence_quality.as_str())
            ));
        }
        report.push('\n');
    }

    report.push_str("## 采集失败\n\n");
    if collection_errors.is_empty() {
        report.push_str("未记录采集失败。\n\n");
    } else {
        for error in collection_errors.iter().take(10) {
            report.push_str(&format!(
                "- {} 对 {} 执行 {}：{}\n",
                zh::source_label(&error.source),
                error.path,
                zh::operation_label(&error.operation),
                zh::message_label(&error.message)
            ));
        }
        report.push('\n');
    }

    report.push_str("## 人工复核清单\n\n");
    if correlation.high_risk_events.is_empty() {
        report.push_str("- 如结合外部事件背景仍有疑点，再复核原始 findings 明细。\n");
    } else {
        report.push_str(
            "- 优先查看 `findings/high_risk_events.csv`，逐条核对来源文件、行号或证据哈希。\n",
        );
        report
            .push_str("- 在把“未发现证据”解读为“正常”前，先检查 `findings/evidence_gaps.csv`。\n");
        report.push_str("- 将 `findings/attack_ip_stats.csv` 与业务归属和预期流量对照。\n");
        report.push_str("- 升级处置前，复核关联进程、网络、持久化和近期文件证据。\n");
    }
    report.push('\n');

    report.push_str("## 备注\n\n");
    if summary.notes.is_empty() {
        report.push_str("- 无备注。\n");
    } else {
        for note in &summary.notes {
            report.push_str(&format!("- {}\n", zh::note_label(note)));
        }
    }

    report
}

fn push_finding_group(report: &mut String, title: &str, findings: &[Finding]) {
    report.push_str(&format!("### {title}\n\n"));
    if findings.is_empty() {
        report.push_str("未记录。\n\n");
        return;
    }
    for finding in findings.iter().take(10) {
        report.push_str(&format!(
            "- [{}] {}：{}（分数 {}，来源 {}）\n",
            zh::severity_label(finding.severity.as_str()),
            finding.rule_id,
            zh::finding_title(&finding.rule_name),
            finding.score,
            finding
                .source_file
                .as_deref()
                .map(|source| format!(
                    "{}{}",
                    source,
                    finding
                        .line_number
                        .map(|line| format!(":{line}"))
                        .unwrap_or_default()
                ))
                .unwrap_or_else(|| "无数据".to_string())
        ));
    }
    report.push('\n');
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RunSummary, TimeRange};

    #[test]
    fn summary_report_matches_golden() {
        let summary = RunSummary {
            tool_version: "1.0.0".to_string(),
            command: "scan".to_string(),
            started_at: "2026-05-15T00:00:00Z".to_string(),
            finished_at: "2026-05-15T00:00:01Z".to_string(),
            output_dir: "results_test".to_string(),
            privilege: "user_or_unknown".to_string(),
            offline: true,
            redact: false,
            formats: vec!["jsonl".to_string(), "csv".to_string(), "md".to_string()],
            time_range: TimeRange {
                mode: "recent_hours".to_string(),
                since: Some("2026-05-14T19:00:00Z".to_string()),
                until: Some("2026-05-15T00:00:00Z".to_string()),
                hours: Some(5),
            },
            files_scanned: 0,
            lines_parsed: 0,
            findings_count: 0,
            collection_errors: 0,
            parse_errors: 0,
            notes: vec!["sample note.".to_string()],
        };

        assert_eq!(
            render_summary_report(&summary, &[], &[], &[], &CorrelationReport::default()),
            include_str!("../../tests/golden/summary_report.md")
        );
    }
}
