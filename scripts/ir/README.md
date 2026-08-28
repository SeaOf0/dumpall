# 补充应急采集脚本

这些脚本用于补充 `dumpall triage` 的主机证据，不替代主程序的采集、检测、时间线和证据包。脚本只在本机读数据或复制证据；不会执行清理、隔离、提权、爆破或网络探测。

## 运行原则

- 在目标机上使用与系统匹配的目录：Linux 只运行 `linux/`，Windows 只运行 `windows/`。
- 输出目录必须是新的、权限受限的目录。脚本会写 `status.tsv`、`SHA256SUMS.txt`；复制类脚本还写证据复制清单。
- 推荐先运行 `dumpall triage`，再运行脚本并将两个结果目录一起带回分析机。脚本结果以原始 `.txt`、`.tsv`、`.csv` 和复制文件为主，便于人工复核及 LLM 分析。
- “没有输出”不能直接解释为“没有对象”：必须查看 `status.tsv`、脚本输出中的错误、`evidence_copy_manifest.tsv` 和主程序的 `collection_errors.csv`/`evidence_gaps.csv`。
- 原始日志、hive、历史和远控配置可能包含凭据或个人信息。只在受控证据盘保存，并按 `SHA256SUMS.txt` 校验；脚本不会复制浏览器 Cookie、登录密码或云凭据内容。

## Linux

```bash
sudo ./linux/run_all.sh --output /secure/ir/linux-extra
```

`run_all.sh` 顺序固定为：

1. `01_volatile_context.sh`：系统、进程树、命令行、`/proc`（status/maps/fd/ns/cgroup/mountinfo）、socket/路由/邻居/DNS、systemd、审计/journal、nftables/iptables、eBPF、keyring、lsof。
2. `02_filesystem_metadata.sh`：近 N 天 bodyfile、未知 UID/GID、ACL、`lsattr` 不可变/追加属性、coredump、binfmt_misc、挂载及 inode 使用率。
3. `03_application_artifacts.sh`：浏览器历史数据库和下载记录的元数据/哈希、shell/client history、rclone/cloud/远程管理配置的元数据/哈希、Docker/containerd/Kubernetes 状态。

可选 `--parallel` 只允许第 2、3 组并发，且同时满足内存至少 4 GiB、CPU 至少 4 核、平均负载低于核数；第 1 组始终先串行完成。`04_targeted_memory.sh` 不会被 `run_all.sh` 自动调用：

```bash
sudo ./linux/04_targeted_memory.sh --output /secure/ir/linux-memory \
  --pid 1234 --pid 5678

# 只有已评估影响、磁盘空间和 gdb/gcore 来源后才启用：
sudo ./linux/04_targeted_memory.sh --output /secure/ir/linux-memory \
  --pid 1234 --capture-dump --gcore /trusted/usr/bin/gcore
```

默认只取显式 PID 的 maps/status/fd 等元数据；`--capture-dump` 逐个执行 `gcore`，检查可用空间并设置 300 秒超时。它不是物理内存镜像，也不能替代 LiME/AVML 等经验证的采集器。

## Windows

管理员 PowerShell 5.1+：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\windows\Run-All.ps1 -Output D:\ir\windows-extra
```

模块说明：

- `01-VolatileContext.ps1`：系统、带 owner 的进程、模块/线程、TCP/UDP、DNS/路由/邻居、命名管道、SMB 会话/打开文件、驱动、服务/任务、WMI 订阅、BITS、Defender 和防火墙。
- `02-ForensicArtifacts.ps1`：事件日志配置、USN Journal 元数据、影子副本/还原点、Prefetch、Amcache、SRUM、PCA、任务、WER、Defender、SetupAPI、Firewall 日志，以及离线用户 NTUSER/UsrClass、Jump List、LNK、RDP cache、ActivitiesCache 的受限复制。
- `03-ApplicationArtifacts.ps1`：Chrome/Edge/Brave/Firefox History/places/downloads 和 PowerShell history 的受限复制；云、rclone、AnyDesk、RustDesk、TeamViewer 配置只记录元数据/哈希；同时登记远程管理进程、容器和 WSL。
- `04-TargetedMemory.ps1`：只对显式 `-ProcessId`（`-Pid` 别名）采集进程、模块、线程；附带 `-CaptureDump -ProcDumpPath` 才逐 PID 生成 dump。

```powershell
.\windows\04-TargetedMemory.ps1 -Output D:\ir\memory `
  -ProcessId 1234,5678

# ProcDump 必须是可信、签名有效的副本；逐进程串行、5 分钟超时、空间不足自动跳过：
.\windows\04-TargetedMemory.ps1 -Output D:\ir\memory `
  -ProcessId 1234 -CaptureDump -ProcDumpPath D:\tools\procdump64.exe
```

`Run-All.ps1 -Parallel` 只有在至少 4 GiB RAM、4 个逻辑核且 CPU 负载低于 70% 时并发文件/应用模块；易失信息始终先串行。需要 USN 记录而不是仅 Journal 元数据时显式增加 `-CollectUsn`，脚本最多保留 50000 行以避免无限输出。内存脚本不会自动运行，也不会把完整 dump 放进 ZIP。

## 证据与盲区

`dumpall` 与脚本的结果应合并分析：主程序负责统一 schema、规则、时间线、报告和 evidence pack；脚本负责补齐主程序不宜默认做的深层枚举和大体积/敏感文件的人工确认。仍需外置工具或离线分析的内容包括：物理 RAM、内核级 rootkit/隐藏对象、完整 MFT/删除恢复、浏览器数据库语义解析、Windows Amcache/SRUM/UserAssist/Shimcache 专项解析、网络 PCAP、云控制面和 EDR/SIEM 历史。缺失技术能力会记录为缺口，不能当作“未发现攻击”。
