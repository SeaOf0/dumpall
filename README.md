# dumpall 主机应急响应工具

只读、离线优先的 Linux / Windows 主机应急响应工具。它在目标机上采集主机状态、进程、网络、账户、持久化、日志、Web 文件、主机事件和可选内存线索，并生成可带回分析机复核的报告与证据包。

完整参数和操作流程以 [`使用手册.md`](使用手册.md) 为准；

- 只读和离线优先；不执行利用、爆破、提权、清痕、隔离或自动修复。
- 所有输出是证据和线索，需要人工复核，不单独构成入侵结论。
- 发布包按目标平台提供独立二进制；Windows 二进制不在 Linux 上运行，Linux 二进制不在 Windows 上运行。

---

## 常用方式

按文件修改时间定位新出现工具：

```bash
./dumpall scan --updatetime --since 2026-08-23T00:00:00+08:00 --until 2026-08-26T23:59:59+08:00 --output ./updated-files
```

结果查看 `findings/updated_files.csv`；完整参数和限制见 [`使用手册.md`](使用手册.md)。

```bash
# 一键全量采集（Linux 建议 root；Windows 用管理员 cmd/PowerShell）
sudo ./dumpall triage --output /secure-volume/out1

# 需要低影响内存取证时在同一次运行中启用（推荐先用）
sudo ./dumpall triage --memory-triage --output /secure-volume/out-memory-triage

# 只有在磁盘空间和业务影响已评估后，才另建目录做全量/逐进程内存镜像
sudo ./dumpall triage --memory-dump --output /secure-volume/out-memory
```

## 命令解析

| 命令 | 用途 | 典型场景 |
|---|---|---|
| `triage` | 一键全量：采集+解析+37 规则检测+攻击链+报告+打包 | **应急主场景**，默认 triage 档（全开） |
| `scan`（一般scan最快） | 完整排查（与 triage 同流水线，档位自选） | 定期巡检、按需组合 |
| `collect` | 仅采集主机上下文，不跑检测 | 只取证据不分析 |
| `analyze` | 仅分析指定路径（无主机采集） | 分析机离线复检 |
| `rules validate` | 校验内置/自定义规则 | 规则维护 |

## 常用参数

```text
路径输入（可重复，文件或目录）：
  -w/--web-path        Web 根目录            -l/--log-path   Web 访问日志
  --db-log-path        数据库日志            --db-type       auto/mysql/mariadb/postgresql/mssql
  --waf-log-path       WAF/CDN 日志          --app-log-path  应用日志
  --evtx-path / --journal-path / --audit-log-path   事件日志（host-ir/triage 档自动采集默认路径）

采集控制：
  --memory-triage      低影响进程内存取证（maps、匿名/可执行片段）
  --memory-dump        原生全量/逐进程内存获取（Linux root / Windows 管理员）
  --memory-tool PATH   外置内存工具路线（输出 raw/memory.bin，登记哈希）
  --updatetime         扫描系统内指定时间段 mtime 的文件，标记可疑工具名称
  --copy-raw / --no-copy-raw   原始证据副本开关（triage 默认开）
  --redact             脱敏 Cookie/token/密码/连接串等敏感值

时间窗口：
-t/--time-range 小时（默认 72，即最近 3 天）；
--log-days 事件窗口（默认 30 天）；
--since / --until 显式边界；
--tz-offset 指定无时区日志（数据库/应用/WAF）的时区偏移（如 +08:00，离线分析机与被检主机时区不一致时建议显式指定）；
--full-scan 不限窗口

文件时间线：
--updatetime 结合上述时间窗口，输出 findings/updated_files.csv。

输出：
-o/--output 目录（默认 results_时间戳）；
--format jsonl,csv,md,html。核心 collection/findings 文件固定保留 CSV/JSONL；该参数用于报告格式元数据，不会把所有结构化证据改成 TXT。

triage 证据：
evidence/suspicious_files/ 保存命中文件、可疑进程可执行文件和输入日志源；
evidence/evidence_copy_manifest.csv 提供逐文件哈希与复制状态。
--no-copy-raw 同时关闭 raw 和该证据副本。

上限：--max-file-size 512(MB) --max-event-records 200000 --max-depth 8 --threads --max-cpu
规则：--rules 额外规则文件/目录；--allowlist 误报抑制 TOML
```

## 结果目录

```
结果目录/
├── reports/report.html        # 总览、高危事件、攻击链、证据缺口
├── reports/dumpall_report.xlsx # 单文件合并报告：全部 CSV 各成一个 sheet
├── findings/
│   ├── findings.csv           # 全部规则命中（含规则 ID/评分/证据摘要）
│   ├── high_risk_events.csv   # 高危/严重
│   ├── memory_strings.csv     # 内存转储可疑字符串（有 dump 才有）
│   ├── memory_triage.csv      # 低影响 maps/内存片段清单（--memory-triage）
│   └── evidence_gaps.csv      # 没采到什么——盲区可见，缺失≠干净
├── collection/                # 33+ 个痕迹清单（history/登录史/持久化/注册表/…）
├── events/  parsed/           # 事件与日志的规范化解析结果
├── raw/                       # 固定原始证据副本+SHA256 清单；memory.bin；hives/
├── evidence/                  # file_hashes.csv；triage 的 suspicious_files/ 证据副本及清单
├── timeline/                  # 时间线与攻击链
└── evidence_pack/             # triage 包含 raw 与发现项证据副本的 zip
```

排查思路建议：`report.html` 定位高危 → `findings/` 看命中明细 → `timeline/attack_chains.md` 串时间线 → `raw/` 用 Volatility/注册表工具深挖 → `evidence_gaps.csv` 确认盲区后决定补充采集。

最简单的方式——结果丢给AI分析，非常方便，已经实际测过了（当前护网中用它抓到了攻击者的PsExec工具以及PSEXEC.EXE-*.pf，从而分析出攻击者利用PsExec的相关横向操作）

## 构建方式

```bash
sh scripts/build-matrix.sh check   # 7 目标交叉编译检查（无需链接器）
sh scripts/build-matrix.sh build   # 构建可链接目标到 dist/
```
