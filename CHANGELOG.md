# Changelog

## 1.0.0 - 首个发布版本

只读、离线优先的 Linux / Windows 主机应急响应工具：在目标机上一键采集"被攻击痕迹"，
断网环境可用，结果打包带回分析机离线复检。所有输出均为可疑证据/线索，需人工复核。

### 采集能力
- 基础快照：系统信息、进程与进程树、网络连接（含进程映射）、账户与登录痕迹、
  定时任务、启动项、服务、Web 根目录与日志候选、指定时间窗内修改的文件。
- Linux 扩展：cron/systemd 持久化（含 timer）、ld.so.preload、内核模块与参数、
  SUID/能力、全局可写、双扩展伪装、二进制目录变更、已装软件包、wtmp/btmp/lastlog
  登录记录、auth/secure/audit 日志、journald 自动导出（新版发行版无 rsyslog 兜底）。
- Windows 扩展：注册表持久化与 hive 原件导出、WMI 订阅、计划任务 XML、回收站 $I、
  LNK/BITS/PS alias/SDB/用户目录、隐藏账户比对（注册表与 Win32 差集）、证书存储、
  RDP 客户端痕迹、环境变量全量、事件日志全通道（含应用程序和服务日志树与自定义视图）。
- 日志解析：Web 访问日志（nginx/apache/iis 等）、MySQL/MariaDB/PostgreSQL/SQL Server、
  WAF/CDN/反向代理、应用框架日志；支持 gzip、BOM/UTF-16 导出、传统 syslog 时间戳；
  GBK 等非 UTF-8 内容有损保留并登记解析错误，不静默丢弃。
- 容器与编排：节点侧 docker/containerd 元数据与日志、Kubernetes 静态 manifest
  解析（多文档 YAML、hostPath 挂载按名配对），不进入容器执行命令。
- 运行时组件静态排查：Tomcat/IIS/Spring 结构化清单，不 attach JVM。
- 内存线索（可选）：低影响进程内存分诊（maps 与受限匿名/可执行片段）、原生内存
  获取（Linux /proc/kcore、Windows 逐进程 minidump）、外置工具接入、内存字符串提取。
- 原始证据副本与证据包：关键日志/配置整份带走；证据包含逐文件 SHA256 清单、
  打包时哈希与内容一致性校验，TAR 支持 GNU longname（超长/多字节路径）。

### 检测能力
- 内置 57 条 YAML 规则 + 5 条内置聚合规则：Web 攻击（SQLi/RCE/LFI/XSS/上传/
  SSRF/扫描/爆破）、主机痕迹（持久化、隧道工具、横向移动、反取证、后门端口、
  外传、勒索准备、挖矿端口、内核参数篡改、文件系统异常）、数据库/WAF/应用异常。
- 时间语义：事件窗口默认 30 天（--log-days/--since/--until/--full-scan）；
  --tz-offset 指定无时区日志的时区偏移；采集侧全量保留解析结果，检测侧按窗口
  过滤；时间戳缺失的事件保守保留并单独计数。
- 误报控制：allowlist 支持 CIDR/路径/UA/规则抑制，未知条目显式告警；302 不计
  登录失败；聚合窗口要求可解析时间戳；URL 匹配含大小写不敏感百分号解码。
- 关联与时间线：统一时间线、攻击链（共同键约束防跨源误并）、IP 富化、
  离线 IOC/GeoIP、基线对比降权。
- 报告：markdown/HTML（转义收口）、SARIF、单 xlsx 多 sheet、CSV 公式注入防护。

### 稳定性与资源边界
- 多字节字符（中文日志/路径）全链路安全；内部异常保留已采集证据并落盘说明。
- 体量防护：内存获取按进程体量与磁盘余量预检；原始副本总量与剩余空间门限；
  大文件与解压流均有上限；遍历有深度/数量/字节三重限制。
- 输出目录已存在即拒绝覆盖；敏感字段脱敏（--redact）。

### 构建
- 发布矩阵：Windows amd64/x86/arm64；Linux amd64/x86/arm64/arm32（musl 静态）。
- 默认特性即可用；启用 binary-evtx 特性获得二进制 EVTX 原生解析。
