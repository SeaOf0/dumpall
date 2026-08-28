use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::profile::ScanProfile;

#[derive(Debug, Parser)]
#[command(
    name = "dumpall",
    version,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    about = "只读、离线优先的主机应急响应与 Web 入侵排查工具",
    long_about = "dumpall 用于授权场景下的主机应急响应与 Web 入侵排查。一条命令采集被攻击痕迹：历史命令、持久化（计划任务/启动项/注册表/cron/systemd）、完整进程与网络连接、登录与暴破记录、事件日志（默认近 30 天，--since/--until 可调）、可疑文件、内存转储等；产出 findings、统一时间线、合并 Excel 与证据包。只读取证，不做漏洞利用、爆破、主动扫描或自动处置。\n\nWindows 版只做 Windows 采集，Linux 版只做 Linux 采集；参数跨平台一致，内容自动对应当前系统。"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// 显示帮助信息。
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    pub help: Option<bool>,

    /// 显示版本信息。
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    pub version: Option<bool>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// 执行完整排查：采集主机上下文、解析日志、运行检测规则并生成报告。
    Scan(ScanArgs),
    /// 仅采集主机侧上下文，不做深度规则检测和攻击链分析。
    Collect(CollectArgs),
    /// 仅分析用户指定的日志/证据路径，不做自动主机发现。
    Analyze(AnalyzeArgs),
    /// 应急采集模式：一键全量采集主机攻击痕迹（历史命令、持久化、登录记录、系统日志、注册表等）并打包。
    Triage(TriageArgs),
    /// 单项导出：按类别导出日志/定时任务/网络连接/进程；参数跨平台一致，内容自动对应当前系统。
    Export(ExportArgs),
    /// 规则维护命令。
    Rules(RulesArgs),
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// 打印本次只读执行计划后退出，不真正采集、解析或检测。
    #[arg(long)]
    pub dry_run_plan: bool,
}

#[derive(Debug, Args)]
pub struct CollectArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Args)]
pub struct TriageArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportKind {
    /// 导出全部系统日志：Windows 导出 EVTX 事件日志通道；Linux 导出 /var/log 全量（含轮转）。支持 --since/--until 时间范围过滤解析事件。
    Logs,
    /// 导出定时任务与启动项：Windows 导出计划任务与启动文件夹；Linux 导出 cron/systemd/rc 等启动面。
    Tasks,
    /// 导出网络连接：Windows/Linux 各自的连接表（含进程映射）与 DNS/防火墙等网络上下文。
    Net,
    /// 导出进程：完整进程列表与进程树（Windows/Linux 各自实现）。
    Proc,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// 要导出的类别：logs / tasks / net / proc。
    #[arg(value_enum)]
    pub what: ExportKind,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RuleCommands,
}

#[derive(Debug, Subcommand)]
pub enum RuleCommands {
    /// 校验内置规则和用户提供的 YAML 规则文件。
    Validate(RuleValidateArgs),
}

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct RuleValidateArgs {
    /// 额外规则文件或规则目录，可重复指定。
    #[arg(long = "rules", value_name = "path")]
    pub rules: Vec<PathBuf>,

    /// 显示当前命令的帮助信息。
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    pub help: Option<bool>,
}

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct CommonArgs {
    /// 最近分析时间窗口，单位为小时；默认只看最近 3 天（72 小时）。
    #[arg(long = "time-range", short = 't', value_name = "hours")]
    pub time_range: Option<u64>,

    /// 扫描系统范围内修改时间落在 --since/--until 或 --time-range 内的文件。
    /// 用于定位新出现的工具、脚本、WebShell 和其他时间线线索。
    #[arg(long = "updatetime")]
    pub updatetime: bool,

    /// 事件日志采集窗口，单位为天；默认 30 天，常用 3/7/14/30。
    /// 0 非法（如需不设窗口请用 --full-scan）；超过 30 天需用 --since/--until 手动指定。
    #[arg(long = "log-days", value_name = "days")]
    pub log_days: Option<u64>,

    /// 明确指定开始时间，支持 RFC3339 或 YYYY-MM-DD HH:MM:SS；优先于 --log-days。
    #[arg(long, value_name = "datetime")]
    pub since: Option<String>,

    /// 明确指定结束时间；不指定时默认到当前时间。
    #[arg(long, value_name = "datetime")]
    pub until: Option<String>,

    /// 无时区时间戳（多数数据库/应用/WAF 日志）的时区偏移，如 +08:00。
    /// 默认取分析机系统时区；离线分析机与被检主机时区不一致时建议显式指定，
    /// 否则跨日志源的时间对齐与关联窗口会整体偏移。
    #[arg(long = "tz-offset", value_name = "offset")]
    pub tz_offset: Option<String>,

    /// 手动指定 Web 根目录，可重复指定；用于文件采集和静态 WebShell 线索检查。
    #[arg(long = "web-path", short = 'w', value_name = "path")]
    pub web_path: Vec<PathBuf>,

    /// 手动指定 Web 访问日志文件或目录，可重复指定；analyze 模式通常至少需要它或其他证据输入。
    #[arg(long = "log-path", short = 'l', value_name = "path")]
    pub log_path: Vec<PathBuf>,

    /// 数据库类型提示，可选 auto/mysql/mariadb/postgresql/mssql；默认 auto 自动判断。
    #[arg(long = "db-type", value_name = "type", default_value = "auto")]
    pub db_type: String,

    /// 手动指定数据库日志文件或目录，可重复指定；用于数据库侧异常和 Web-to-DB 关联。
    #[arg(long = "db-log-path", value_name = "path")]
    pub db_log_path: Vec<PathBuf>,

    /// 手动指定 WAF、CDN 或反向代理日志文件/目录，可重复指定；用于补充拦截和放行上下文。
    #[arg(long = "waf-log-path", value_name = "path")]
    pub waf_log_path: Vec<PathBuf>,

    /// 手动指定应用框架日志文件或目录，可重复指定；用于应用异常、SQL 错误、SSRF 错误等上下文。
    #[arg(long = "app-log-path", value_name = "path")]
    pub app_log_path: Vec<PathBuf>,

    /// Web 中间件提示：nginx/apache/tomcat/iis/weblogic/jboss/spring/django/flask/node/php/aspnet/caddy。
    #[arg(long, short = 'm', value_name = "type")]
    pub middleware: Option<String>,

    /// 扫描配置档；quick 为默认轻量流程，full-ir/runtime/host-ir/container-ir 会启用更多证据范围。
    #[arg(long, value_enum, default_value_t = ScanProfile::Quick)]
    pub profile: ScanProfile,

    /// 生成统一时间线和攻击链输出。
    #[arg(long)]
    pub timeline: bool,

    /// 生成 SARIF 报告，便于平台或审计工具导入。
    #[arg(long)]
    pub sarif: bool,

    /// 指定历史 dumpall 结果目录作为本地基线；重复证据会降权但不会删除。
    #[arg(long = "baseline", value_name = "results_dir")]
    pub baseline: Option<PathBuf>,

    /// 启用内置 WebShell/静态文件线索检查；full-ir 配置档也会启用。
    #[arg(long = "static-scan")]
    pub static_scan: bool,

    /// 指定 YARA 规则文件或目录，可重复指定；需要带 YARA 支持的构建，否则记录为能力边界。
    #[arg(long = "yara-rules", value_name = "path")]
    pub yara_rules: Vec<PathBuf>,

    /// 指定可信代理 CIDR 或单个 IP；只有可信代理来源才会采信 X-Forwarded-For 等真实客户端 IP 头。
    #[arg(long = "trusted-proxy", value_name = "cidr")]
    pub trusted_proxy: Vec<String>,

    /// 指定离线 GeoIP/ASN 数据库路径；默认支持 CSV/JSON，MMDB 依赖 geoip feature。
    #[arg(long = "geoip-db", value_name = "path")]
    pub geoip_db: Option<PathBuf>,

    /// 指定本地 IOC 文件，支持 CSV/JSON/纯文本，可重复指定；只做离线匹配。
    #[arg(long = "ioc", value_name = "path")]
    pub ioc: Vec<PathBuf>,

    /// 启用运行时组件静态排查；默认不做 JVM attach、heap dump 或主动运行时查询。
    #[arg(long = "runtime-scan")]
    pub runtime_scan: bool,

    /// 运行时目标提示：auto/java/iis/aspnet。
    #[arg(long = "runtime-target", value_name = "target", default_value = "auto")]
    pub runtime_target: String,

    /// Java 运行时目录，仅作为离线路径上下文；默认不会 attach JVM。
    #[arg(long = "java-home", value_name = "path")]
    pub java_home: Option<PathBuf>,

    /// Tomcat CATALINA_BASE 或离线提取的 Tomcat 目录，可重复指定。
    #[arg(long = "tomcat-base", value_name = "path")]
    pub tomcat_base: Vec<PathBuf>,

    /// Spring Boot 应用目录或 jar/war 路径，可重复指定。
    #[arg(long = "spring-app-path", value_name = "path")]
    pub spring_app_path: Vec<PathBuf>,

    /// IIS applicationHost.config 路径，用于静态解析站点、模块、handler 和应用池线索。
    #[arg(long = "iis-config", value_name = "path")]
    pub iis_config: Option<PathBuf>,

    /// Windows 事件文件或目录，可重复指定；支持二进制 .evtx（官方构建已启用）与 XML/JSON/JSONL 离线解析。
    #[arg(long = "evtx-path", value_name = "path")]
    pub evtx_path: Vec<PathBuf>,

    /// 离线 journald 导出文件或目录，可重复指定；二进制 journald 不伪解析。
    #[arg(long = "journal-path", value_name = "path")]
    pub journal_path: Vec<PathBuf>,

    /// Linux auditd/auth.log 日志路径，可重复指定。
    #[arg(long = "audit-log-path", value_name = "path")]
    pub audit_log_path: Vec<PathBuf>,

    /// 容器运行时提示：auto/docker/containerd；只解析节点侧元数据和日志。
    #[arg(
        long = "container-runtime",
        value_name = "runtime",
        default_value = "auto"
    )]
    pub container_runtime: String,

    /// 容器日志目录或文件，可重复指定；不会执行 container exec。
    #[arg(long = "container-log-path", value_name = "path")]
    pub container_log_path: Vec<PathBuf>,

    /// Kubernetes 节点侧静态 Pod 配置或日志路径，可重复指定；不会调用 Kubernetes API。
    #[arg(long = "k8s-node-path", value_name = "path")]
    pub k8s_node_path: Vec<PathBuf>,

    /// 在报告生成后输出 evidence pack，包含摘要、索引、哈希和复核指南。
    #[arg(long = "evidence-pack")]
    pub evidence_pack: bool,

    /// evidence pack 格式：zip 或 tar；默认 zip。
    #[arg(long = "pack-format", value_name = "zip|tar", default_value = "zip")]
    pub pack_format: String,

    /// 运行时组件基线文件或结果目录，用于标记新增组件；不删除、不隔离、不修复。
    #[arg(long = "component-baseline", value_name = "path")]
    pub component_baseline: Option<PathBuf>,

    /// 保持运行时主动检查关闭；这是默认安全边界。
    #[arg(long = "no-runtime-active-check")]
    pub no_runtime_active_check: bool,

    /// 显式允许低影响本地运行时查询；默认不启用，仍不得进行破坏性操作。
    #[arg(long = "runtime-active-check")]
    pub runtime_active_check: bool,

    /// 每个事件源最多解析的事件数量；默认 200000。
    #[arg(long = "max-event-records", value_name = "n")]
    pub max_event_records: Option<u64>,

    /// 输出目录；默认 results_YYYYMMDD_HHMMSS，已存在时会拒绝覆盖。
    #[arg(long, short = 'o', value_name = "dir")]
    pub output: Option<PathBuf>,

    /// 报告格式元数据，逗号分隔：jsonl,csv,md,html；核心 collection/findings 文件仍固定保留 CSV/JSONL，默认记录全部格式。
    #[arg(
        long = "format",
        value_name = "jsonl,csv,md,html",
        value_delimiter = ','
    )]
    pub format: Vec<String>,

    /// 对指定日志做全量分析，不套用最近时间窗口。
    #[arg(long)]
    pub full_scan: bool,

    /// CPU 使用目标百分比，记录到运行计划与 system_info；默认 50。当前版本为记录值，不做强制限流。
    #[arg(long = "max-cpu", value_name = "percent")]
    pub max_cpu: Option<u8>,

    /// 最大工作线程数；默认 min(4, CPU/2)。
    #[arg(long, value_name = "n")]
    pub threads: Option<usize>,

    /// 单个文件读取上限，单位 MB；默认 512（.evtx 事件通道按下限 2048 执行）。
    #[arg(long = "max-file-size", value_name = "mb")]
    pub max_file_size: Option<u64>,

    /// 内置静态扫描的单文件上限，单位 MB；默认 10。
    #[arg(long = "max-static-file-size", value_name = "mb")]
    pub max_static_file_size: Option<u64>,

    /// YARA 扫描的单文件上限，单位 MB；默认 20。
    #[arg(long = "max-yara-file-size", value_name = "mb")]
    pub max_yara_file_size: Option<u64>,

    /// Web 目录遍历最大深度；默认 8。
    #[arg(long = "max-depth", value_name = "n")]
    pub max_depth: Option<usize>,

    /// 脱敏 Cookie、Authorization、token、password、session、JWT、连接串等敏感值。
    #[arg(long)]
    pub redact: bool,

    /// 额外规则文件或规则目录，可重复指定；与内置规则一起校验和执行。
    #[arg(long = "rules", value_name = "path")]
    pub rules: Vec<PathBuf>,

    /// 误报白名单 TOML 文件，用于按路径、IP、User-Agent、规则等抑制噪声。
    #[arg(long, value_name = "path")]
    pub allowlist: Option<PathBuf>,

    /// 外置内存获取工具路径（如 avml / winpmem）；指定后 dumpall 会以输出目录内
    /// raw/memory.bin 为输出参数调用它，仅做只读内存获取并登记哈希。
    #[arg(long = "memory-tool", value_name = "path")]
    pub memory_tool: Option<PathBuf>,

    /// dumpall 原生内存获取（无需外置工具）：Linux 经 /proc/kcore 或 /dev/mem
    /// 写 LiME 格式 raw/memory.bin（需 root）；Windows 提权 SeDebugPrivilege 后
    /// 逐进程 MiniDumpWriteDump 全内存转储到 raw/memory_dumps/（需管理员）。
    #[arg(long = "memory-dump")]
    pub memory_dump: bool,

    /// 低影响进程内存取证：只读取可疑进程的 maps 和受限匿名/可执行内存片段，
    /// 不暂停进程、不读取整机物理内存；用于发现内存马、注入代码和 deleted 映射。
    #[arg(long = "memory-triage")]
    pub memory_triage: bool,

    /// 把关键原始证据（日志、配置、crontab、authorized_keys 等）复制进结果目录 raw/ 并生成哈希清单；默认在 triage 模式开启。
    #[arg(long = "copy-raw")]
    pub copy_raw: bool,

    /// 关闭原始证据复制；优先级高于 --copy-raw 和 triage 默认值。
    #[arg(long = "no-copy-raw", conflicts_with = "copy_raw")]
    pub no_copy_raw: bool,

    /// 生成合并 Excel 报告 reports/dumpall_report.xlsx（每个采集类别一个 sheet）；triage 模式默认开启。
    #[arg(long = "xlsx-report")]
    pub xlsx_report: bool,

    /// 关闭合并 Excel 报告；优先级高于 --xlsx-report 和 triage 默认值。
    #[arg(long = "no-xlsx-report", conflicts_with = "xlsx_report")]
    pub no_xlsx_report: bool,

    /// 保持网络访问关闭；这是默认值，当前版本不提供关闭离线模式的反向参数。
    #[arg(long, default_value_t = true)]
    pub offline: bool,

    /// 输出更详细的进度信息到 stderr 和 run.log。
    #[arg(long)]
    pub verbose: bool,

    /// 显示当前命令的帮助信息。
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    pub help: Option<bool>,
}
