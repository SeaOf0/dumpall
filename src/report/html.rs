use std::collections::BTreeSet;
use std::path::Path;

use crate::correlation::CorrelationReport;
use crate::error::Result;
use crate::model::{CollectionError, EvidenceGap, Finding, RunSummary, Severity};
use crate::output::writers;
use crate::report::zh;

pub fn write_html_report(
    path: &Path,
    summary: &RunSummary,
    findings: &[Finding],
    collection_errors: &[CollectionError],
    evidence_gaps: &[EvidenceGap],
    correlation: &CorrelationReport,
) -> Result<()> {
    writers::write_text(
        path,
        &render_html_report(
            summary,
            findings,
            collection_errors,
            evidence_gaps,
            correlation,
        ),
    )
}

pub fn render_html_report(
    summary: &RunSummary,
    findings: &[Finding],
    collection_errors: &[CollectionError],
    evidence_gaps: &[EvidenceGap],
    correlation: &CorrelationReport,
) -> String {
    let critical = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|finding| finding.severity == Severity::High)
        .count();
    let top_source = correlation.attack_ip_stats.first();
    let top_chain = correlation.attack_chains.first();
    let headline = executive_headline(critical, high, correlation);
    let base_info = BaseInfo::from_output_dir(Path::new(&summary.output_dir));

    let mut report = String::new();
    report.push_str("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n");
    report.push_str("<meta charset=\"utf-8\">\n");
    report.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    report.push_str("<title>dumpall 应急排查报告</title>\n");
    report.push_str("<style>\n");
    report.push_str(STYLE);
    report.push_str("</style>\n</head>\n<body>\n");
    report.push_str("<main class=\"shell\">\n");

    report.push_str("<section class=\"hero\">\n");
    report.push_str("<div>\n<p class=\"eyebrow\">dumpall 应急排查</p>\n");
    report.push_str(&format!("<h1>{}</h1>\n", escape_html(&headline)));
    report.push_str(&format!(
        "<p class=\"subtle\">执行命令：{}。开始时间：{}，结束时间：{}。以下发现均为可疑证据，需人工复核，不代表最终入侵定性。</p>\n",
        escape_html(&summary.command),
        escape_html(&summary.started_at),
        escape_html(&summary.finished_at)
    ));
    report.push_str("</div>\n");
    report.push_str("<div class=\"hero-card\">\n");
    report.push_str(&metric("发现数量", &summary.findings_count.to_string()));
    report.push_str(&metric("高危/严重", &(high + critical).to_string()));
    report.push_str(&metric(
        "攻击链",
        &correlation.attack_chains.len().to_string(),
    ));
    report.push_str(&metric("证据缺口", &evidence_gaps.len().to_string()));
    report.push_str("</div>\n</section>\n");

    report.push_str("<section class=\"grid two\">\n");
    report.push_str("<article class=\"panel verdict\">\n<h2>总体判断</h2>\n");
    report.push_str("<dl class=\"facts\">\n");
    report.push_str(&fact(
        "主要来源 IP",
        top_source.map(|row| row.remote_ip.as_str()),
    ));
    report.push_str(&fact("主要类型", top_category(correlation).as_deref()));
    report.push_str(&fact(
        "最高链路等级",
        top_chain.map(|chain| chain.evidence_chain_level.as_str()),
    ));
    report.push_str(&fact(
        "主要受影响路径",
        top_path(correlation).filter(|value| !value.is_empty()),
    ));
    report.push_str("</dl>\n");
    report.push_str("<p class=\"callout\">建议从这里开始：先核对疑似攻击入口，再沿攻击链查看相关证据，最后确认证据缺口。CSV/JSON 文件仍作为可复核审计记录保留。</p>\n");
    report.push_str("</article>\n");

    report.push_str("<article class=\"panel\">\n<h2>复核路径</h2>\n<ol class=\"steps\">\n");
    report.push_str(
        "<li><strong>确认入口。</strong>查看疑似攻击入口中的来源 IP、URL、时间和规则。</li>\n",
    );
    report.push_str("<li><strong>追踪链路。</strong>对比 Web、文件、主机、运行时、WAF、应用和容器侧证据。</li>\n");
    report.push_str("<li><strong>关注缺口。</strong>缺少某类证据源不等于该来源干净，只能说明本次运行未覆盖。</li>\n");
    report
        .push_str("<li><strong>按需展开明细。</strong>需要深挖时再打开底部的原始表格链接。</li>\n");
    report.push_str("</ol>\n</article>\n</section>\n");

    push_base_info_section(&mut report, &base_info);

    report.push_str("<section class=\"panel\">\n<h2>疑似攻击入口</h2>\n");
    if let Some(source) = top_source {
        report.push_str("<div class=\"entry\">\n");
        report.push_str(&entry_item("来源 IP", &source.remote_ip));
        report.push_str(&entry_item("发现数", &source.findings.to_string()));
        report.push_str(&entry_item("最高分", &source.max_score.to_string()));
        report.push_str(&entry_item(
            "类型",
            display_or(&zh::category_label(&source.categories), "无数据"),
        ));
        report.push_str(&entry_item(
            "主要路径",
            display_or(&source.top_paths, "无数据"),
        ));
        report.push_str(&entry_item(
            "首次出现",
            display_or(&source.first_seen, "无数据"),
        ));
        report.push_str(&entry_item(
            "最后出现",
            display_or(&source.last_seen, "无数据"),
        ));
        report.push_str("</div>\n");
    } else {
        report.push_str("<p class=\"empty\">当前证据中无法推导疑似攻击来源 IP。</p>\n");
    }
    report.push_str("</section>\n");

    report.push_str("<section class=\"panel\">\n<h2>攻击链摘要</h2>\n");
    if correlation.attack_chains.is_empty() {
        report.push_str("<p class=\"empty\">未形成多证据攻击链。</p>\n");
    } else {
        report.push_str("<div class=\"chains\">\n");
        for chain in correlation.attack_chains.iter().take(6) {
            report.push_str("<article class=\"chain\">\n");
            report.push_str(&format!(
                "<div class=\"chain-head\"><span class=\"badge level\">{}</span><strong>{}</strong><span>最高分 {}</span></div>\n",
                escape_html(&chain.evidence_chain_level),
                escape_html(&chain.chain_id),
                chain.max_score
            ));
            report.push_str("<dl class=\"facts compact\">\n");
            report.push_str(&fact(
                "时间范围",
                chain_time_range(chain.first_seen.as_str(), chain.last_seen.as_str()).as_deref(),
            ));
            report.push_str(&fact("来源 IP", some_non_empty(&chain.remote_ips)));
            report.push_str(&fact("路径", some_non_empty(&chain.paths)));
            let chain_categories = zh::category_label(&chain.categories);
            report.push_str(&fact("类型", Some(&chain_categories)));
            report.push_str(&fact("发现 ID", Some(&chain.finding_ids.join("; "))));
            report.push_str("</dl>\n");
            report.push_str(&format!(
                "<p class=\"summary-line\">{}</p>\n",
                escape_html(display_or(&chain.summary, "无链路摘要。"))
            ));
            if !chain.evidence_chain_basis.is_empty() {
                report.push_str(&format!(
                    "<p class=\"basis\">{}</p>\n",
                    escape_html(&chain.evidence_chain_basis)
                ));
            }
            report.push_str("</article>\n");
        }
        report.push_str("</div>\n");
    }
    report.push_str("</section>\n");

    report.push_str("<section class=\"panel\">\n<h2>高危证据</h2>\n");
    if correlation.high_risk_events.is_empty() {
        report.push_str("<p class=\"empty\">未产生高危或严重级别发现。</p>\n");
    } else {
        report.push_str("<div class=\"table-wrap\"><table><thead><tr>");
        for header in [
            "级别",
            "分数",
            "规则",
            "时间",
            "来源",
            "路径/IP",
            "证据链",
            "建议",
        ] {
            report.push_str(&format!("<th>{header}</th>"));
        }
        report.push_str("</tr></thead><tbody>\n");
        for event in correlation.high_risk_events.iter().take(25) {
            report.push_str("<tr>");
            report.push_str(&td_badge(
                &event.severity,
                zh::severity_label(&event.severity),
            ));
            report.push_str(&td(&event.score.to_string()));
            report.push_str(&td(&format!(
                "{} / {} / {}",
                event.rule_id,
                zh::finding_title(&event.rule_id),
                zh::category_label(&event.category)
            )));
            report.push_str(&td(display_or(&event.timestamp, "无数据")));
            report.push_str(&td(&source_location(
                &event.source_file,
                &event.line_number,
            )));
            report.push_str(&td(display_or(
                &event.uri_path,
                display_or(&event.remote_ip, "无数据"),
            )));
            report.push_str(&td(&format!(
                "{}: {}",
                event.evidence_chain_level,
                zh::message_label(&event.evidence_chain)
            )));
            report.push_str(&td(&zh::recommendation_label(&event.recommendation)));
            report.push_str("</tr>\n");
        }
        report.push_str("</tbody></table></div>\n");
    }
    report.push_str("</section>\n");

    report.push_str("<section class=\"grid two\">\n");
    report.push_str("<article class=\"panel\">\n<h2>攻击类型</h2>\n");
    if correlation.attack_type_stats.is_empty() {
        report.push_str("<p class=\"empty\">未产生攻击类型统计。</p>\n");
    } else {
        report.push_str("<ul class=\"rank-list\">\n");
        for row in correlation.attack_type_stats.iter().take(8) {
            report.push_str(&format!(
                "<li><strong>{}</strong><span>{} 条发现，{} 条高危/严重，最高分 {}</span><small>{}</small></li>\n",
                escape_html(&zh::category_label(&row.category)),
                row.findings,
                row.high_or_critical,
                row.max_score,
                escape_html(display_or(&row.affected_paths, display_or(&row.affected_ips, "无数据")))
            ));
        }
        report.push_str("</ul>\n");
    }
    report.push_str("</article>\n");

    report.push_str("<article class=\"panel\">\n<h2>受影响 URL</h2>\n");
    if correlation.affected_url_stats.is_empty() {
        report.push_str("<p class=\"empty\">未产生受影响 URL 统计。</p>\n");
    } else {
        report.push_str("<ul class=\"rank-list\">\n");
        for row in correlation.affected_url_stats.iter().take(8) {
            report.push_str(&format!(
                "<li><strong>{}</strong><span>{} 条发现，最高分 {}</span><small>{}</small></li>\n",
                escape_html(&row.uri_path),
                row.findings,
                row.max_score,
                escape_html(display_or(
                    &zh::category_label(&row.categories),
                    display_or(&row.remote_ips, "无数据")
                ))
            ));
        }
        report.push_str("</ul>\n");
    }
    report.push_str("</article>\n</section>\n");

    report.push_str("<section class=\"grid two\">\n");
    report.push_str("<article class=\"panel\">\n<h2>可疑文件</h2>\n");
    push_csv_records(&mut report, &correlation.suspicious_files, "path", "reason");
    report.push_str("</article>\n");
    report.push_str("<article class=\"panel\">\n<h2>近期 Web 文件变更</h2>\n");
    push_csv_records(
        &mut report,
        &correlation.recent_web_files,
        "path",
        "modified_at",
    );
    report.push_str("</article>\n</section>\n");

    report.push_str("<section class=\"panel\">\n<h2>证据缺口与采集健康</h2>\n");
    report.push_str("<div class=\"health\">\n");
    report.push_str(&metric("扫描文件", &summary.files_scanned.to_string()));
    report.push_str(&metric("解析行数", &summary.lines_parsed.to_string()));
    report.push_str(&metric("采集错误", &collection_errors.len().to_string()));
    report.push_str(&metric("解析错误", &summary.parse_errors.to_string()));
    report.push_str("</div>\n");
    if evidence_gaps.is_empty() {
        report.push_str("<p class=\"empty\">未记录提升为证据缺口的问题。</p>\n");
    } else {
        report.push_str("<div class=\"table-wrap\"><table><thead><tr><th>来源</th><th>路径</th><th>状态</th><th>含义</th><th>建议</th></tr></thead><tbody>\n");
        for gap in evidence_gaps.iter().take(20) {
            report.push_str("<tr>");
            report.push_str(&td(&zh::source_label(&gap.source)));
            report.push_str(&td(display_or(&gap.path, "未指定")));
            report.push_str(&td(&format!(
                "{} / {}",
                zh::coverage_status_label(gap.coverage_status.as_str()),
                zh::evidence_quality_label(gap.evidence_quality.as_str())
            )));
            report.push_str(&td(&zh::message_label(&gap.message)));
            report.push_str(&td(&zh::recommendation_label(&gap.recommendation)));
            report.push_str("</tr>\n");
        }
        report.push_str("</tbody></table></div>\n");
    }
    report.push_str("</section>\n");

    report.push_str("<section class=\"panel\">\n<h2>源文件索引</h2>\n");
    report.push_str("<div class=\"links\">\n");
    for (label, href) in [
        ("Markdown 摘要", "summary_report.md"),
        ("高危证据表", "../findings/high_risk_events.csv"),
        ("全部发现", "../findings/findings.csv"),
        ("攻击来源统计", "../findings/attack_ip_stats.csv"),
        ("攻击类型统计", "../findings/attack_type_stats.csv"),
        ("证据缺口", "../findings/evidence_gaps.csv"),
        ("时间线 CSV", "../timeline/timeline.csv"),
        ("攻击链 Markdown", "../timeline/attack_chains.md"),
        ("证据索引", "../evidence_pack/evidence_index.csv"),
        ("运行清单", "../manifest.json"),
    ] {
        report.push_str(&format!(
            "<a href=\"{}\">{}</a>\n",
            escape_attr(href),
            escape_html(label)
        ));
    }
    report.push_str("</div>\n");
    report.push_str("</section>\n");

    report.push_str("<footer>由 dumpall 生成。请将本 HTML 与原始结果目录一起保存，以保证链接可正常打开。</footer>\n");
    report.push_str("</main>\n</body>\n</html>\n");
    report
}

#[derive(Debug, Default)]
struct BaseInfo {
    hostname: String,
    os: String,
    arch: String,
    current_user: String,
    privilege: String,
    timezone: String,
    web_paths: Vec<String>,
    log_paths: Vec<String>,
    middleware: Vec<String>,
    web_roots: Vec<PathSummary>,
    discovered_logs: Vec<PathSummary>,
    db_logs: Vec<PathSummary>,
}

#[derive(Debug, Clone)]
struct PathSummary {
    label: String,
    path: String,
    detail: String,
    exists: String,
}

impl BaseInfo {
    fn from_output_dir(output_dir: &Path) -> Self {
        let mut info = Self::default();
        let collection_dir = output_dir.join("collection");
        info.load_system_info(&collection_dir.join("system_info.json"));
        info.middleware = read_middleware(&collection_dir.join("middleware.csv"));
        info.web_roots = read_path_summaries(
            &collection_dir.join("web_roots.csv"),
            "middleware",
            "Web 根目录",
            8,
        );
        info.discovered_logs = read_path_summaries(
            &collection_dir.join("discovered_logs.csv"),
            "middleware",
            "Web 日志",
            8,
        );
        info.db_logs = read_path_summaries(
            &collection_dir.join("discovered_db_logs.csv"),
            "db_type",
            "数据库日志",
            8,
        );
        info
    }

    fn load_system_info(&mut self, path: &Path) {
        let Ok(content) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            return;
        };
        self.hostname = json_string(&value, "hostname");
        self.os = json_string(&value, "os");
        self.arch = json_string(&value, "arch");
        self.current_user = json_string(&value, "current_user");
        self.privilege = json_string(&value, "privilege");
        self.timezone = json_string(&value, "timezone");
        self.web_paths = json_string_array(&value, "web_paths");
        self.log_paths = json_string_array(&value, "log_paths");
    }
}

fn push_base_info_section(report: &mut String, info: &BaseInfo) {
    report.push_str("<section class=\"panel\">\n<h2>系统基础信息</h2>\n");
    report.push_str("<dl class=\"facts base-facts\">\n");
    report.push_str(&fact("主机名", non_empty(&info.hostname)));
    report.push_str(&fact("操作系统", non_empty(&info.os)));
    report.push_str(&fact("系统架构", non_empty(&info.arch)));
    report.push_str(&fact("当前用户", non_empty(&info.current_user)));
    report.push_str(&fact("权限状态", non_empty(&info.privilege)));
    report.push_str(&fact("时区", non_empty(&info.timezone)));
    report.push_str(&fact(
        "用户指定 Web 路径",
        joined_or_none(&info.web_paths).as_deref(),
    ));
    report.push_str(&fact(
        "用户指定日志路径",
        joined_or_none(&info.log_paths).as_deref(),
    ));
    report.push_str(&fact(
        "发现的 Web 中间件",
        joined_or_none(&info.middleware).as_deref(),
    ));
    report.push_str("</dl>\n");

    report.push_str("<div class=\"grid three base-grid\">\n");
    push_path_summary_card(report, "Web 根目录", &info.web_roots);
    push_path_summary_card(report, "Web 日志路径", &info.discovered_logs);
    push_path_summary_card(report, "数据库日志路径", &info.db_logs);
    report.push_str("</div>\n");
    report.push_str("</section>\n");
}

fn push_path_summary_card(report: &mut String, title: &str, rows: &[PathSummary]) {
    report.push_str("<article class=\"mini-panel\">\n");
    report.push_str(&format!("<h3>{}</h3>\n", escape_html(title)));
    if rows.is_empty() {
        report.push_str("<p class=\"empty\">未采集到相关路径。</p>\n");
    } else {
        report.push_str("<ul class=\"path-list\">\n");
        for row in rows {
            report.push_str(&format!(
                "<li><strong>{}</strong><span>{}</span><small>{} / {}</small></li>\n",
                escape_html(&row.path),
                escape_html(&row.detail),
                escape_html(&row.label),
                escape_html(&row.exists)
            ));
        }
        report.push_str("</ul>\n");
    }
    report.push_str("</article>\n");
}

fn read_middleware(path: &Path) -> Vec<String> {
    let Ok(mut reader) = csv::Reader::from_path(path) else {
        return Vec::new();
    };
    let headers = match reader.headers() {
        Ok(headers) => headers.clone(),
        Err(_) => return Vec::new(),
    };
    let kind_index = header_index(&headers, "kind");
    let evidence_index = header_index(&headers, "evidence");
    let confidence_index = header_index(&headers, "confidence");
    let mut values = BTreeSet::new();
    for record in reader.records().flatten() {
        let kind = get_record_value(&record, kind_index);
        if kind.is_empty() {
            continue;
        }
        let evidence = get_record_value(&record, evidence_index);
        let confidence = get_record_value(&record, confidence_index);
        let mut label = kind.to_string();
        let mut details = Vec::new();
        if !confidence.is_empty() {
            details.push(format!("置信度 {confidence}"));
        }
        if !evidence.is_empty() {
            details.push(evidence.to_string());
        }
        if !details.is_empty() {
            label.push_str(&format!("（{}）", details.join("，")));
        }
        values.insert(label);
    }
    values.into_iter().take(8).collect()
}

fn read_path_summaries(
    path: &Path,
    label_field: &str,
    fallback_label: &str,
    limit: usize,
) -> Vec<PathSummary> {
    let Ok(mut reader) = csv::Reader::from_path(path) else {
        return Vec::new();
    };
    let headers = match reader.headers() {
        Ok(headers) => headers.clone(),
        Err(_) => return Vec::new(),
    };
    let path_index = header_index(&headers, "path");
    let label_index = header_index(&headers, label_field);
    let source_index = header_index(&headers, "source");
    let exists_index = header_index(&headers, "exists");
    let notes_index = header_index(&headers, "notes");
    let evidence_index = header_index(&headers, "evidence");

    let mut rows = Vec::new();
    for record in reader.records().flatten() {
        let path_value = get_record_value(&record, path_index);
        if path_value.is_empty() {
            continue;
        }
        let label = display_or(get_record_value(&record, label_index), fallback_label).to_string();
        let source = get_record_value(&record, source_index);
        let notes = get_record_value(&record, notes_index);
        let evidence = get_record_value(&record, evidence_index);
        let exists = match get_record_value(&record, exists_index)
            .to_ascii_lowercase()
            .as_str()
        {
            "true" => "存在",
            "false" => "未发现",
            "" => "未知",
            other => other,
        }
        .to_string();
        let detail = [source, notes, evidence]
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join("，");
        rows.push(PathSummary {
            label,
            path: path_value.to_string(),
            detail: if detail.is_empty() {
                "无补充说明".to_string()
            } else {
                detail
            },
            exists,
        });
        if rows.len() >= limit {
            break;
        }
    }
    rows
}

fn header_index(headers: &csv::StringRecord, name: &str) -> Option<usize> {
    headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case(name))
}

fn get_record_value(record: &csv::StringRecord, index: Option<usize>) -> &str {
    index
        .and_then(|index| record.get(index))
        .map(str::trim)
        .unwrap_or_default()
}

fn json_string(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn json_string_array(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn joined_or_none(values: &[String]) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        Some(values.join("; "))
    }
}

fn executive_headline(critical: usize, high: usize, correlation: &CorrelationReport) -> String {
    if let Some(chain) = correlation.attack_chains.first() {
        let source = if chain.remote_ips.is_empty() {
            "无数据".to_string()
        } else {
            chain.remote_ips.clone()
        };
        let paths = if chain.paths.is_empty() {
            "无数据".to_string()
        } else {
            chain.paths.clone()
        };
        return format!(
            "{} 证据链：{} -> {}",
            chain.evidence_chain_level, source, paths
        );
    }
    if let Some(source) = correlation.attack_ip_stats.first() {
        return format!(
            "发现来自 {} 的可疑活动，最高分 {}",
            source.remote_ip, source.max_score
        );
    }
    if critical + high > 0 {
        return format!("{critical} 条严重、{high} 条高危发现需要复核");
    }
    "本次运行未发现高危攻击链".to_string()
}

fn metric(label: &str, value: &str) -> String {
    format!(
        "<div class=\"metric\"><span>{}</span><strong>{}</strong></div>\n",
        escape_html(label),
        escape_html(value)
    )
}

fn fact(label: &str, value: Option<&str>) -> String {
    format!(
        "<dt>{}</dt><dd>{}</dd>\n",
        escape_html(label),
        escape_html(zh::placeholder_label(
            value.filter(|item| !item.is_empty()).unwrap_or("无数据"),
        ))
    )
}

fn entry_item(label: &str, value: &str) -> String {
    format!(
        "<div><span>{}</span><strong>{}</strong></div>\n",
        escape_html(label),
        escape_html(value)
    )
}

fn td(value: &str) -> String {
    format!("<td>{}</td>", escape_html(value))
}

fn td_badge(class_value: &str, label: &str) -> String {
    format!(
        "<td><span class=\"badge {}\">{}</span></td>",
        escape_attr(&class_value.to_ascii_lowercase()),
        escape_html(label)
    )
}

fn push_csv_records(
    report: &mut String,
    rows: &[crate::correlation::CsvRecord],
    primary: &str,
    secondary: &str,
) {
    if rows.is_empty() {
        report.push_str("<p class=\"empty\">未记录。</p>\n");
        return;
    }
    report.push_str("<ul class=\"rank-list\">\n");
    for row in rows.iter().take(8) {
        let primary_value = row.get(primary).unwrap_or("无数据");
        let secondary_value = row.get(secondary).unwrap_or("无数据");
        report.push_str(&format!(
            "<li><strong>{}</strong><span>{}</span></li>\n",
            escape_html(primary_value),
            escape_html(&zh::message_label(secondary_value))
        ));
    }
    report.push_str("</ul>\n");
}

fn top_category(correlation: &CorrelationReport) -> Option<String> {
    correlation
        .attack_type_stats
        .first()
        .map(|row| zh::category_label(&row.category))
}

fn top_path(correlation: &CorrelationReport) -> Option<&str> {
    correlation
        .affected_url_stats
        .first()
        .map(|row| row.uri_path.as_str())
        .or_else(|| {
            correlation
                .attack_chains
                .first()
                .map(|chain| chain.paths.as_str())
        })
}

fn some_non_empty(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn chain_time_range(first: &str, last: &str) -> Option<String> {
    match (first.is_empty(), last.is_empty()) {
        (true, true) => None,
        (false, true) => Some(first.to_string()),
        (true, false) => Some(last.to_string()),
        (false, false) if first == last => Some(first.to_string()),
        (false, false) => Some(format!("{first} 至 {last}")),
    }
}

fn source_location(source_file: &str, line_number: &str) -> String {
    if source_file.is_empty() {
        return "无数据".to_string();
    }
    if line_number.is_empty() {
        source_file.to_string()
    } else {
        format!("{source_file}:{line_number}")
    }
}

fn display_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_attr(value: &str) -> String {
    escape_html(value)
}

const STYLE: &str = r#"
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --ink: #18202a;
  --muted: #657184;
  --line: #d9dee7;
  --accent: #0f766e;
  --accent-soft: #dff4f1;
  --danger: #b42318;
  --warn: #b54708;
  --info: #1d4ed8;
  --shadow: 0 10px 30px rgba(22, 31, 44, 0.08);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Arial, Helvetica, sans-serif;
  line-height: 1.5;
}
.shell {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 36px;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 18px;
  align-items: stretch;
  margin-bottom: 18px;
}
.hero, .panel {
  background: var(--panel);
  border: 1px solid var(--line);
  box-shadow: var(--shadow);
  border-radius: 8px;
}
.hero { padding: 26px; }
.hero h1 {
  margin: 0;
  font-size: 32px;
  line-height: 1.15;
  letter-spacing: 0;
}
.eyebrow {
  margin: 0 0 8px;
  color: var(--accent);
  font-weight: 700;
  text-transform: uppercase;
  font-size: 12px;
}
.subtle, .empty, .basis, footer {
  color: var(--muted);
}
.hero-card, .health {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}
.metric {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
  background: #fbfcfd;
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: 12px;
}
.metric strong {
  display: block;
  margin-top: 4px;
  font-size: 24px;
}
.grid {
  display: grid;
  gap: 18px;
  margin-bottom: 18px;
}
.grid.two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.grid.three {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.panel {
  padding: 20px;
  margin-bottom: 18px;
}
.mini-panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px;
  background: #fbfcfd;
}
h2 {
  margin: 0 0 14px;
  font-size: 18px;
  letter-spacing: 0;
}
h3 {
  margin: 0 0 10px;
  font-size: 15px;
  letter-spacing: 0;
}
.facts {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 8px 12px;
  margin: 0;
}
.facts.compact { grid-template-columns: 110px minmax(0, 1fr); }
.facts.base-facts {
  grid-template-columns: 150px minmax(0, 1fr) 150px minmax(0, 1fr);
  margin-bottom: 16px;
}
dt {
  color: var(--muted);
}
dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.callout {
  margin: 16px 0 0;
  padding: 12px;
  background: var(--accent-soft);
  border-left: 4px solid var(--accent);
  border-radius: 6px;
}
.steps {
  margin: 0;
  padding-left: 20px;
}
.steps li + li { margin-top: 8px; }
.entry {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}
.entry div {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
  min-width: 0;
}
.entry span {
  display: block;
  color: var(--muted);
  font-size: 12px;
}
.entry strong {
  display: block;
  margin-top: 4px;
  overflow-wrap: anywhere;
}
.chains {
  display: grid;
  gap: 12px;
}
.chain {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px;
  background: #fbfcfd;
}
.chain-head {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.summary-line {
  margin: 12px 0 0;
}
.basis {
  margin: 8px 0 0;
  font-size: 13px;
}
.table-wrap {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  min-width: 900px;
}
th, td {
  border-bottom: 1px solid var(--line);
  padding: 9px 10px;
  text-align: left;
  vertical-align: top;
  font-size: 13px;
}
th {
  color: var(--muted);
  background: #fbfcfd;
  font-weight: 700;
}
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 2px 8px;
  font-size: 12px;
  font-weight: 700;
  color: var(--info);
  background: #dbeafe;
}
.badge.critical { color: var(--danger); background: #fee4e2; }
.badge.high { color: var(--warn); background: #fef0c7; }
.badge.level { color: var(--accent); background: var(--accent-soft); }
.rank-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 10px;
}
.rank-list li {
  display: grid;
  gap: 2px;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fbfcfd;
}
.rank-list strong, .rank-list span, .rank-list small {
  overflow-wrap: anywhere;
}
.rank-list small {
  color: var(--muted);
}
.path-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 10px;
}
.path-list li {
  display: grid;
  gap: 3px;
}
.path-list strong, .path-list span, .path-list small {
  overflow-wrap: anywhere;
}
.path-list span, .path-list small {
  color: var(--muted);
}
.base-grid {
  margin-bottom: 0;
}
.links {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.links a {
  color: var(--accent);
  text-decoration: none;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 8px 10px;
  background: #fbfcfd;
}
footer {
  font-size: 12px;
  padding: 8px 0;
}
@media (max-width: 860px) {
  .hero, .grid.two, .grid.three, .entry {
    grid-template-columns: 1fr;
  }
  .hero-card, .health {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .facts, .facts.compact, .facts.base-facts {
    grid-template-columns: 1fr;
  }
  .shell {
    width: min(100% - 20px, 1180px);
    padding-top: 10px;
  }
  .hero h1 {
    font-size: 24px;
  }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::{AttackChain, AttackIpStat, CorrelationReport, HighRiskEvent};
    use crate::model::{RunSummary, TimeRange};
    use std::fs;

    #[test]
    fn html_report_has_operator_sections_and_escapes_values() {
        let output_dir = unique_temp_dir("dumpall-html-report");
        fs::create_dir_all(output_dir.join("collection")).unwrap();
        fs::write(
            output_dir.join("collection").join("system_info.json"),
            r#"{
  "hostname": "web01",
  "os": "linux",
  "arch": "x86_64",
  "timezone": "Asia/Shanghai",
  "current_user": "root",
  "privilege": "admin",
  "web_paths": ["/var/www/html"],
  "log_paths": ["/var/log/nginx/access.log"]
}"#,
        )
        .unwrap();
        fs::write(
            output_dir.join("collection").join("middleware.csv"),
            "kind,source,evidence,confidence,notes\nnginx,process,nginx master,high,\n",
        )
        .unwrap();
        fs::write(
            output_dir.join("collection").join("web_roots.csv"),
            "path,source,middleware,priority,exists,readable,notes,evidence\n/var/www/html,manual,nginx,10,true,true,用户指定,manual path\n",
        )
        .unwrap();
        fs::write(
            output_dir.join("collection").join("discovered_logs.csv"),
            "path,source,middleware,priority,exists,notes,evidence\n/var/log/nginx/access.log,manual,nginx,10,true,用户指定,manual path\n",
        )
        .unwrap();
        fs::write(
            output_dir.join("collection").join("discovered_db_logs.csv"),
            "path,source,db_type,priority,exists,notes,evidence\n/var/log/mysql/mysql.log,manual,mysql,10,true,用户指定,manual path\n",
        )
        .unwrap();
        let summary = RunSummary {
            tool_version: "1.2.0".to_string(),
            command: "analyze".to_string(),
            started_at: "2026-05-17T12:00:00Z".to_string(),
            finished_at: "2026-05-17T12:00:01Z".to_string(),
            output_dir: output_dir.display().to_string(),
            privilege: "user".to_string(),
            offline: true,
            redact: false,
            formats: vec!["jsonl".to_string(), "csv".to_string(), "md".to_string()],
            time_range: TimeRange {
                mode: "full_scan".to_string(),
                since: None,
                until: None,
                hours: None,
            },
            files_scanned: 1,
            lines_parsed: 2,
            findings_count: 1,
            collection_errors: 0,
            parse_errors: 0,
            notes: Vec::new(),
        };
        let mut correlation = CorrelationReport::default();
        correlation.attack_ip_stats.push(AttackIpStat {
            remote_ip: "203.0.113.10".to_string(),
            findings: 2,
            total_score: 180,
            max_score: 95,
            highest_severity: "critical".to_string(),
            categories: "rce".to_string(),
            top_paths: "/api/run?<script>".to_string(),
            first_seen: "2026-05-17T12:00:00Z".to_string(),
            last_seen: "2026-05-17T12:00:10Z".to_string(),
        });
        correlation.attack_chains.push(AttackChain {
            chain_id: "CHAIN-000001".to_string(),
            evidence_chain_level: "L4".to_string(),
            evidence_chain_basis: "host behavior correlation".to_string(),
            max_score: 95,
            highest_severity: "critical".to_string(),
            first_seen: "2026-05-17T12:00:00Z".to_string(),
            last_seen: "2026-05-17T12:00:10Z".to_string(),
            remote_ips: "203.0.113.10".to_string(),
            paths: "/api/run?<script>".to_string(),
            categories: "rce".to_string(),
            finding_ids: vec!["F-000001".to_string()],
            summary: "http -> process".to_string(),
        });
        correlation.high_risk_events.push(HighRiskEvent {
            finding_id: "F-000001".to_string(),
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            evidence_quality: "Q2".to_string(),
            score: 95,
            category: "rce".to_string(),
            rule_id: "WEB-RCE-001".to_string(),
            timestamp: "2026-05-17T12:00:00Z".to_string(),
            remote_ip: "203.0.113.10".to_string(),
            uri_path: "/api/run?<script>".to_string(),
            source_file: "access.log".to_string(),
            line_number: "10".to_string(),
            related_ids: "F-000002".to_string(),
            evidence_chain_level: "L4".to_string(),
            evidence_chain: "related F-000002".to_string(),
            recommendation: "Review".to_string(),
        });

        let html = render_html_report(&summary, &[], &[], &[], &correlation);

        assert!(html.contains("疑似攻击入口"));
        assert!(html.contains("攻击链摘要"));
        assert!(html.contains("系统基础信息"));
        assert!(html.contains("web01"));
        assert!(html.contains("x86_64"));
        assert!(html.contains("nginx"));
        assert!(html.contains("/var/www/html"));
        assert!(html.contains("/var/log/mysql/mysql.log"));
        assert!(html.contains("源文件索引"));
        assert!(html.contains("203.0.113.10"));
        assert!(html.contains("/api/run?&lt;script&gt;"));
        assert!(!html.contains("/api/run?<script>"));

        fs::remove_dir_all(output_dir).unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        crate::unique_test_dir(prefix)
    }
}
