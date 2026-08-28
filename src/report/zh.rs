pub fn severity_label(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "严重",
        "high" => "高危",
        "medium" => "中危",
        "low" => "低危",
        "info" => "信息",
        _ => value,
    }
}

pub fn confidence_label(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "high" => "高",
        "medium" => "中",
        "low" => "低",
        _ => value,
    }
}

pub fn evidence_quality_label(value: &str) -> &str {
    match value.trim() {
        "Q1" => "Q1 直接证据",
        "Q2" => "Q2 强关联证据",
        "Q3" => "Q3 弱关联证据",
        "Q4" => "Q4 环境上下文",
        "Q5" => "Q5 采集缺口",
        _ => value,
    }
}

pub fn coverage_status_label(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "collected" => "已采集",
        "partial" => "部分采集",
        "not_collected" => "未采集",
        "unsupported" => "不支持",
        _ => value,
    }
}

pub fn time_range_mode_label(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "recent_hours" => "最近时间窗口",
        "full_scan" => "全量分析",
        "explicit" => "指定时间范围",
        _ => value,
    }
}

pub fn bool_label(value: bool) -> &'static str {
    if value {
        "是"
    } else {
        "否"
    }
}

pub fn placeholder_label(value: &str) -> &str {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "n/a" | "none" | "unknown" | "unknown source" | "unknown path" => "无数据",
        "not limited" => "未限制",
        "unspecified" | "unspecified path" => "未指定",
        "user_or_unknown" => "普通用户或未知",
        _ => value,
    }
}

pub fn category_label(value: &str) -> String {
    if value.trim().is_empty() {
        return "无数据".to_string();
    }
    value
        .split([';', ','])
        .map(|item| {
            let trimmed = item.trim();
            let label = match trimmed.to_ascii_lowercase().as_str() {
                "sqli" | "sql_injection" => "SQL 注入",
                "rce" | "command_execution" => "命令执行",
                "lfi" | "path_traversal" => "路径遍历/文件包含",
                "ssrf" => "SSRF",
                "xss" => "XSS",
                "webshell" | "file_upload" => "上传/WebShell 线索",
                "bruteforce" | "brute_force" => "暴力破解",
                "scanner" | "recon" => "扫描/探测",
                "info_leak" | "information_disclosure" => "信息泄露",
                "runtime_component" => "运行时组件风险",
                "host_windows_execution" => "Windows 主机执行证据",
                "host_linux_execution" => "Linux 主机执行证据",
                "persistence_service" => "持久化服务线索",
                "container_escape_risk" => "容器隔离风险",
                "container_sensitive_mount" => "容器敏感挂载",
                "container_log_suspicious" => "容器可疑日志",
                "evidence_gap" => "证据缺口",
                _ => trimmed,
            };
            if label == trimmed {
                trimmed.to_string()
            } else {
                format!("{trimmed}（{label}）")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn source_label(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "system" => "系统信息".to_string(),
        "process" => "进程".to_string(),
        "network" => "网络连接".to_string(),
        "account" => "账户".to_string(),
        "persistence" => "持久化".to_string(),
        "persistence_startup_items" => "启动项持久化".to_string(),
        "filesystem" => "文件系统".to_string(),
        "http_access" => "Web 访问日志".to_string(),
        "db_log" => "数据库日志".to_string(),
        "waf_log" => "WAF/CDN 日志".to_string(),
        "app_log" => "应用日志".to_string(),
        "evidence_gap" => "证据缺口".to_string(),
        "runtime" => "运行时组件".to_string(),
        "container" => "容器".to_string(),
        "events" => "主机事件".to_string(),
        "windows_evtx" => "Windows EVTX".to_string(),
        "linux_audit" => "Linux auditd".to_string(),
        "journald" => "journald".to_string(),
        _ if value.trim().is_empty() => "无数据".to_string(),
        _ => value.to_string(),
    }
}

pub fn operation_label(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "read_file" => "读取文件".to_string(),
        "read_dir" => "读取目录".to_string(),
        "metadata" => "读取元数据".to_string(),
        "file_type" => "读取文件类型".to_string(),
        "scan_web_root" => "扫描 Web 根目录".to_string(),
        "discover" => "发现证据源".to_string(),
        "parse" => "解析".to_string(),
        _ if value.trim().is_empty() => "无数据".to_string(),
        _ => value.to_string(),
    }
}

pub fn finding_title(value: &str) -> String {
    match value.trim() {
        "WEB-SQLI-001" => "HTTP 请求中出现 SQL 注入结构".to_string(),
        "WEB-RCE-001" => "HTTP 请求中出现命令执行特征".to_string(),
        "WEB-LFI-001" => "路径遍历或本地文件包含请求".to_string(),
        "WEB-SSRF-001" => "请求参数包含外部地址或云元数据地址".to_string(),
        "WEB-XSS-LOW-001" => "跨站脚本载荷特征".to_string(),
        "WEB-UPLOAD-001" => "可疑上传或 WebShell 扩展名请求".to_string(),
        "WEB-SCANNER-001" => "扫描器或批量探测特征".to_string(),
        "WEB-BRUTE-001" => "重复失败登录或管理入口认证尝试".to_string(),
        "WEB-INFOLEAK-001" => "敏感文件或备份泄露探测".to_string(),
        "WEB-FRAMEWORK-001" => "框架漏洞利用探测".to_string(),
        "HOST-PROC-001" => "进程清单中出现可疑命令解释器或下载工具".to_string(),
        "HOST-NET-001" => "Web 相关进程存在公网出站连接".to_string(),
        "HOST-PERSIST-001" => "可疑持久化命令".to_string(),
        "DB-AUTH-FAIL-001" => "数据库认证失败证据".to_string(),
        "DB-FILE-ACCESS-001" => "数据库文件读写能力调用".to_string(),
        "DB-DELAY-001" => "数据库延时函数或时间盲注特征".to_string(),
        "DB-PRIV-CHANGE-001" => "数据库权限或账户变更语句".to_string(),
        "DB-CODE-EXEC-001" => "数据库命令执行或扩展能力调用".to_string(),
        "DB-ENUM-001" => "数据库元数据枚举语句".to_string(),
        "DB-LINKED-SERVER-001" => "SQL Server 链接服务器访问能力调用".to_string(),
        "WAF-BLOCK-001" => "WAF/CDN 阻断可疑 Web 请求".to_string(),
        "WAF-SUSPICIOUS-ALLOW-001" => "WAF 记录了未阻断的可疑请求".to_string(),
        "APP-EXCEPTION-001" => "应用错误或异常证据".to_string(),
        "APP-SQL-ERROR-001" => "应用数据库错误证据".to_string(),
        "APP-SSRF-ERROR-001" => "应用出站请求或 SSRF 风格错误".to_string(),
        "APP-DESERIALIZATION-001" => "应用反序列化或框架解析错误".to_string(),
        "GAP-PERSISTENCE-STARTUP-ITEMS-UNAVAILABLE-001" => {
            "启动项证据源不可用或采集不完整".to_string()
        }
        "Evidence source unavailable or incomplete" => "证据源不可用或采集不完整".to_string(),
        "SQL injection structure in HTTP request" => "HTTP 请求中出现 SQL 注入结构".to_string(),
        "Command execution tokens in HTTP request" => "HTTP 请求中出现命令执行特征".to_string(),
        "Path traversal or local file inclusion request" => {
            "路径遍历或本地文件包含请求".to_string()
        }
        "External or metadata URL in request parameter" => {
            "请求参数包含外部地址或云元数据地址".to_string()
        }
        "Cross-site scripting payload marker" => "跨站脚本载荷特征".to_string(),
        "Suspicious upload or WebShell extension in request" => {
            "可疑上传或 WebShell 扩展名请求".to_string()
        }
        "Scanner or broad probing fingerprint" => "扫描器或批量探测特征".to_string(),
        "Repeated failed login or admin authentication attempt" => {
            "重复失败登录或管理入口认证尝试".to_string()
        }
        "Sensitive file or backup disclosure probe" => "敏感文件或备份泄露探测".to_string(),
        "Framework exploitation probe" => "框架漏洞利用探测".to_string(),
        "Suspicious command interpreter or download tool in process inventory" => {
            "进程清单中出现可疑命令解释器或下载工具".to_string()
        }
        "Web process outbound public network connection" => {
            "Web 相关进程存在公网出站连接".to_string()
        }
        "Suspicious persistence command" => "可疑持久化命令".to_string(),
        "Database authentication failure evidence" => "数据库认证失败证据".to_string(),
        "Database file read or write primitive" => "数据库文件读写能力调用".to_string(),
        "Database delay function or timing primitive" => "数据库延时函数或时间盲注特征".to_string(),
        "Database privilege or account change statement" => "数据库权限或账户变更语句".to_string(),
        "Database command execution or extension primitive" => {
            "数据库命令执行或扩展能力调用".to_string()
        }
        "Database metadata enumeration statement" => "数据库元数据枚举语句".to_string(),
        "SQL Server linked server access primitive" => {
            "SQL Server 链接服务器访问能力调用".to_string()
        }
        "WAF or CDN blocked suspicious Web request" => "WAF/CDN 阻断可疑 Web 请求".to_string(),
        "WAF logged suspicious request without blocking" => {
            "WAF 记录了未阻断的可疑请求".to_string()
        }
        "Application error or exception evidence" => "应用错误或异常证据".to_string(),
        "Application database error evidence" => "应用数据库错误证据".to_string(),
        "Application outbound request or SSRF-style error" => {
            "应用出站请求或 SSRF 风格错误".to_string()
        }
        "Application deserialization or framework parser error" => {
            "应用反序列化或框架解析错误".to_string()
        }
        "Built-in WebShell static file indicators" => "内置 WebShell 静态文件特征".to_string(),
        "Local offline IOC match" => "本地离线 IOC 命中".to_string(),
        _ if value.trim().is_empty() => "无数据".to_string(),
        _ => value.to_string(),
    }
}

pub fn message_label(value: &str) -> String {
    let mut output = value.to_string();
    for (from, to) in [
        ("Evidence gap in", "证据缺口出现在"),
        ("during", "执行"),
        ("persistence file could not be read", "持久化文件无法读取"),
        (
            "This means the run cannot confirm absence of evidence for that source.",
            "这表示本次运行无法确认该证据源中不存在相关证据。",
        ),
        (
            "stream did not contain valid UTF-8",
            "数据流包含非 UTF-8 内容",
        ),
        (
            "line contained invalid UTF-8 and was decoded lossily",
            "该行包含非 UTF-8 内容，已使用有损解码继续解析",
        ),
        ("missing database timestamp", "缺少数据库时间戳"),
        (
            "line exceeded max line length and was truncated",
            "该行超过最大长度，已截断处理",
        ),
        ("not proof of compromise", "不是入侵定论"),
        ("Treat as suspicious evidence", "按可疑证据处理"),
        ("Review", "复核"),
    ] {
        output = output.replace(from, to);
    }
    output
}

pub fn recommendation_label(value: &str) -> String {
    match value.trim() {
        "Review permissions, path existence, and log availability for this evidence source before treating the run as complete." => {
            "在将本次运行视为完整前，复核该证据源的权限、路径是否存在以及日志可用性。".to_string()
        }
        "Review surrounding requests, application errors, and affected parameter handling." => {
            "复核前后请求、应用错误，以及受影响参数的服务端处理逻辑。".to_string()
        }
        "Check whether a Web-facing process spawned a shell, script interpreter, or download tool near this time." => {
            "检查相近时间内 Web 暴露进程是否启动了 shell、脚本解释器或下载工具。".to_string()
        }
        "Confirm whether the requested path returned sensitive content or application errors." => {
            "确认该请求路径是否返回敏感内容或触发应用错误。".to_string()
        }
        "Review server-side URL fetch behavior and outbound network evidence." => {
            "复核服务端 URL 拉取行为和出站网络证据。".to_string()
        }
        "Treat as low-confidence evidence unless paired with application logs or stored payload confirmation." => {
            "除非有应用日志或存储型载荷证据配合，否则按低置信度证据处理。".to_string()
        }
        "Correlate with recent Web directory file changes and subsequent access to uploaded files." => {
            "关联近期 Web 目录文件变更以及后续对上传文件的访问。".to_string()
        }
        "Aggregate by source IP and only escalate if paired with successful exploitation evidence." => {
            "按来源 IP 聚合；只有结合成功利用证据时再升级处置优先级。".to_string()
        }
        "Review authentication logs for account spray patterns and eventual success." => {
            "复核认证日志，确认是否存在账号喷洒以及后续成功登录。".to_string()
        }
        "Check the actual response, file presence, and Web root exposure." => {
            "核对实际响应内容、文件是否存在，以及 Web 根目录暴露情况。".to_string()
        }
        "Identify the framework in use and review corresponding application and middleware logs." => {
            "确认所用框架，并复核对应应用日志和中间件日志。".to_string()
        }
        "Review parent process, start time, command line, and nearby Web requests before escalation." => {
            "升级前复核父进程、启动时间、命令行和相近 Web 请求。".to_string()
        }
        "Verify whether the outbound endpoint is expected for the application." => {
            "确认该出站目标是否属于应用预期行为。".to_string()
        }
        "Review task, startup item, or service origin and creation time without modifying it." => {
            "在不修改目标的前提下，复核任务、启动项或服务来源及创建时间。".to_string()
        }
        "Review adjacent database and Web authentication evidence before treating this as credential attack activity." => {
            "在认定为凭据攻击前，复核相邻数据库和 Web 认证证据。".to_string()
        }
        "Check whether the database account should be able to access server files and correlate with Web root changes." => {
            "确认数据库账号是否应具备服务器文件访问能力，并关联 Web 根目录变更。".to_string()
        }
        "Correlate with SQL injection HTTP requests and application response-time anomalies." => {
            "关联 SQL 注入 HTTP 请求和应用响应时间异常。".to_string()
        }
        "Verify whether this database account or role change is expected maintenance activity." => {
            "确认该数据库账号或角色变更是否属于预期维护操作。".to_string()
        }
        "Review whether the database feature or stored procedure is expected and correlate with host process evidence." => {
            "复核该数据库功能或存储过程是否预期存在，并关联主机进程证据。".to_string()
        }
        "Treat metadata enumeration as weak evidence unless paired with Web SQLi or privilege/file access activity." => {
            "除非结合 Web SQL 注入或权限/文件访问活动，否则按弱证据处理元数据枚举。".to_string()
        }
        "Review whether linked-server access is expected for this application account." => {
            "复核该应用账号是否应访问链接服务器。".to_string()
        }
        "Treat WAF/CDN activity as context; review whether later Web or application evidence suggests bypass or impact." => {
            "将 WAF/CDN 活动作为上下文，继续复核后续 Web 或应用证据是否显示绕过或影响。".to_string()
        }
        "Check adjacent access logs and application errors to determine whether this logged request reached vulnerable code." => {
            "检查相邻访问日志和应用错误，判断该请求是否到达易受影响代码路径。".to_string()
        }
        "Correlate the exception with HTTP status 500, source IP, request ID, and database or file evidence." => {
            "将异常与 HTTP 500、来源 IP、请求 ID、数据库或文件证据关联分析。".to_string()
        }
        "Review nearby SQL injection requests and database logs; this is suspicious evidence, not proof of exploitation." => {
            "复核相近 SQL 注入请求和数据库日志；这是可疑证据，不是成功利用定论。".to_string()
        }
        "Correlate with SSRF-like HTTP parameters and outbound network evidence before escalation." => {
            "升级前关联 SSRF 风格 HTTP 参数和出站网络证据。".to_string()
        }
        "Compare with framework probe requests and review whether the exception is expected for normal traffic." => {
            "对照框架探测请求，复核该异常是否可能来自正常流量。".to_string()
        }
        _ => message_label(value),
    }
}

pub fn note_label(value: &str) -> String {
    let trimmed = value.trim();
    if let Some((prefix, suffix)) = parse_counts(
        trimmed,
        "basic collectors completed: ",
        " collection error(s), ",
        " filesystem item(s) inspected.",
    ) {
        return format!(
            "基础采集完成：{} 个采集错误，{} 个文件系统条目已检查。",
            prefix, suffix
        );
    }
    if let Some(rest) = trimmed.strip_prefix("discovery completed: ") {
        if let Some((middleware, rest)) = rest.split_once(" middleware candidate(s), ") {
            if let Some((web_roots, rest)) = rest.split_once(" web root candidate(s), ") {
                let logs = rest.strip_suffix(" log path candidate(s).").unwrap_or(rest);
                return format!(
                    "发现完成：{} 个中间件候选，{} 个 Web 根候选，{} 个日志路径候选。",
                    middleware, web_roots, logs
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("parsing completed: ") {
        if let Some((events, rest)) = rest.split_once(" HTTP event(s), ") {
            if let Some((lines, rest)) = rest.split_once(" line(s) inspected, ") {
                let errors = rest.strip_suffix(" parse error(s).").unwrap_or(rest);
                return format!(
                    "Web 日志解析完成：{} 条 HTTP 事件，{} 行已检查，{} 个解析错误。",
                    events, lines, errors
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("detection completed: ") {
        if let Some((rules, rest)) = rest.split_once(" rule(s) loaded, ") {
            if let Some((findings, rest)) = rest.split_once(" finding(s) produced, ") {
                let suppressed = rest.strip_suffix(" finding(s) suppressed.").unwrap_or(rest);
                return format!(
                    "检测完成：加载 {} 条规则，产生 {} 条发现，抑制 {} 条发现。",
                    rules, findings, suppressed
                );
            }
        }
    }
    if let Some((gaps, _)) = parse_counts(
        trimmed,
        "evidence-gap assessment promoted ",
        " collection gap(s) into findings/evidence_gaps.csv and low-severity Q5 findings.",
        "",
    ) {
        return format!("证据缺口评估：{} 个采集缺口已写入 findings/evidence_gaps.csv，并提升为低级别 Q5 发现。", gaps);
    }
    if let Some(rest) = trimmed.strip_prefix("correlation completed: ") {
        if let Some((relations, rest)) = rest.split_once(" relation(s), ") {
            if let Some((high, rest)) = rest.split_once(" high-risk event(s), ") {
                let attack_ips = rest.strip_suffix(" attack IP row(s), 1 attack type row(s).");
                return match attack_ips {
                    Some(ips) => format!(
                        "关联分析完成：{} 个关联，{} 个高危事件，{} 个攻击来源 IP 统计行。",
                        relations, high, ips
                    ),
                    None => format!(
                        "关联分析完成：{} 个关联，{} 个高危事件。",
                        relations, high
                    ),
                };
            }
            let high = rest.strip_suffix(" high-risk event(s)").unwrap_or(rest);
            return format!(
                "关联分析完成：{} 个关联，{} 个高危事件。",
                relations, high
            );
        }
    }
    if let Some((candidates, existing)) = parse_counts(
        trimmed,
        "database discovery completed: ",
        " candidate(s), ",
        " existing path(s).",
    ) {
        return format!(
            "数据库日志发现完成：{} 个候选，{} 个现存路径。",
            candidates, existing
        );
    }
    if let Some(rest) = trimmed.strip_prefix("database parsing completed: ") {
        if let Some((events, rest)) = rest.split_once(" DB event(s), ") {
            if let Some((lines, rest)) = rest.split_once(" line(s) inspected, ") {
                let errors = rest.strip_suffix(" parse error(s).").unwrap_or(rest);
                return format!(
                    "数据库日志解析完成：{} 条数据库事件，{} 行已检查，{} 个解析错误。",
                    events, lines, errors
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("WAF/CDN parsing completed: ") {
        if let Some((events, rest)) = rest.split_once(" WAF event(s), ") {
            if let Some((lines, rest)) = rest.split_once(" line(s) inspected, ") {
                let errors = rest.strip_suffix(" parse error(s).").unwrap_or(rest);
                return format!(
                    "WAF/CDN 解析完成：{} 条 WAF 事件，{} 行已检查，{} 个解析错误。",
                    events, lines, errors
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("application log parsing completed: ") {
        if let Some((events, rest)) = rest.split_once(" app event(s), ") {
            if let Some((lines, rest)) = rest.split_once(" line(s) inspected, ") {
                let errors = rest.strip_suffix(" parse error(s).").unwrap_or(rest);
                return format!(
                    "应用日志解析完成：{} 条应用事件，{} 行已检查，{} 个解析错误。",
                    events, lines, errors
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("enrichment completed: ") {
        if let Some((rows, rest)) = rest.split_once(" IP row(s), ") {
            if let Some((ioc, rest)) = rest.split_once(" IOC match(es), ") {
                let proxy = rest
                    .strip_suffix(" trusted-proxy inference(s).")
                    .unwrap_or(rest);
                return format!(
                    "富化完成：{} 条 IP 富化记录，{} 个 IOC 命中，{} 个可信代理推断。",
                    rows, ioc, proxy
                );
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("static scan completed: ") {
        if let Some((files, rest)) = rest.split_once(" file(s) inspected, ") {
            if let Some((suspicious, rest)) = rest.split_once(" suspicious file row(s), ") {
                let findings = rest.strip_suffix(" finding(s).").unwrap_or(rest);
                return format!(
                    "静态扫描完成：{} 个文件已检查，{} 条可疑文件记录，{} 条发现。",
                    files, suspicious, findings
                );
            }
        }
    }
    if let Some((events, chains)) = parse_counts(
        trimmed,
        "timeline completed: ",
        " timeline event(s), ",
        " attack chain(s).",
    ) {
        return format!(
            "时间线完成：{} 条时间线事件，{} 条攻击链。",
            events, chains
        );
    }
    match trimmed {
        "host collection outputs are evidence inventory and feed detection rules; they are not compromise conclusions by themselves." => {
            "主机采集输出是证据清单，并会输入 规则；它们本身不是入侵结论。".to_string()
        }
        "database log discovery and parsing boundary active" => {
            "数据库日志发现与解析边界已启用。".to_string()
        }
        "WAF/CDN and application log parsing boundary active" => {
            "WAF/CDN 与应用日志解析边界已启用。".to_string()
        }
        "evidence-pack generation active" => {
            "证据包生成已启用。".to_string()
        }
        _ => message_label(trimmed),
    }
}

fn parse_counts<'a>(
    value: &'a str,
    prefix: &str,
    separator: &str,
    suffix: &str,
) -> Option<(&'a str, &'a str)> {
    let rest = value.strip_prefix(prefix)?;
    if suffix.is_empty() {
        return rest
            .split_once(separator)
            .map(|(left, right)| (left.trim(), right.trim()));
    }
    let (left, right) = rest.split_once(separator)?;
    let right = right.strip_suffix(suffix)?;
    Some((left.trim(), right.trim()))
}
