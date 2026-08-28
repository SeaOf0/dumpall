//! Windows 补充采集：驱动清单、DNS 缓存、hosts 文件、共享、防火墙规则、
//! 隐藏账户（SAM 对比）、PowerShell 控制台历史。

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;

use crate::collectors::command::{collect_text_command, CommandSpec};

const DRIVERS_HEADER: &str = "name,display_name,pathname,state,start_mode\r\n";
const DNS_CACHE_HEADER: &str = "entry,record_type,data\r\n";
const DNS_CONFIG_HEADER: &str = "kind,source,key,value\r\n";
const SHARES_HEADER: &str = "name,path,description\r\n";
const FIREWALL_HEADER: &str = "display_name,enabled,direction,action,profile,rule_text\r\n";
const USERS_EXT_HEADER: &str = "name,sid,flag,source\r\n";
const PS_HISTORY_HEADER: &str = "user,path,line_no,command\r\n";
const PROCESS_MODULES_HEADER: &str =
    "pid,process,module,path,base_address,size,company,file_version\r\n";
const PROCESS_THREADS_HEADER: &str = "pid,process,thread_id,start_address,state,wait_reason\r\n";
const NAMED_PIPES_HEADER: &str = "name,path\r\n";
const SMB_HEADER: &str = "kind,client,user,path_or_share,id,detail\r\n";
const DEFENDER_HEADER: &str = "kind,name,value,source\r\n";

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_network(layout, errors)?;
    collect_text_command(
        "drivers",
        &layout.drivers,
        DRIVERS_HEADER,
        &[driver_commands()],
        errors,
        false,
    )?;
    let ps_history = layout.collection_dir.join("powershell_history.csv");
    collect_text_command(
        "powershell_history",
        &ps_history,
        PS_HISTORY_HEADER,
        &[ps_history_commands()],
        errors,
        false,
    )?;
    let hidden_services = layout.collection_dir.join("hidden_services.csv");
    collect_text_command(
        "hidden_services",
        &hidden_services,
        "name,image_path,start_mode,source,flag\r\n",
        &[hidden_service_commands()],
        errors,
        false,
    )?;
    collect_deep_volatile(layout, errors)?;
    let cert_store = layout.collection_dir.join("cert_store.txt");
    collect_text_command(
        "cert_store",
        &cert_store,
        "(certutil -store text export)\r\n",
        // 直跑 certutil 会按中文系统默认 GBK 代码页输出，from_utf8_lossy 会破坏
        // 中文主题/颁发者字段；经 cmd.exe chcp 65001 强制 UTF-8 输出。
        &[CommandSpec::cmd_utf8(
            r"%SystemRoot%\System32\certutil.exe -store -user My",
        )],
        errors,
        false,
    )
}

fn collect_deep_volatile(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_text_command(
        "process_modules",
        &layout.collection_dir.join("process_modules.csv"),
        PROCESS_MODULES_HEADER,
        &[process_modules_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "process_threads",
        &layout.collection_dir.join("process_threads.csv"),
        PROCESS_THREADS_HEADER,
        &[process_threads_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "named_pipes",
        &layout.collection_dir.join("named_pipes.csv"),
        NAMED_PIPES_HEADER,
        &[named_pipe_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "smb_live_context",
        &layout.collection_dir.join("smb_live_context.csv"),
        SMB_HEADER,
        &[smb_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "defender_context",
        &layout.collection_dir.join("defender_context.csv"),
        DEFENDER_HEADER,
        &[defender_commands()],
        errors,
        false,
    )
}

/// Compare SAM account-name keys with the normal local-account enumeration.
///
/// This focused check is part of the basic account snapshot on Windows.  The
/// remaining Windows host-artifact collectors (history, drivers, firewall,
/// shares and certificates) stay triage-only.
pub fn collect_hidden_accounts(
    layout: &OutputLayout,
    errors: &mut Vec<CollectionError>,
) -> Result<()> {
    let users_ext = layout.collection_dir.join("users_hidden_check.csv");
    collect_text_command(
        "hidden_accounts",
        &users_ext,
        USERS_EXT_HEADER,
        &[hidden_account_commands()],
        errors,
        false,
    )
}

/// 注册表 Services 键与 Win32_Service 的差集：仅注册表可见的服务是隐藏服务特征。
fn hidden_service_commands() -> CommandSpec {
    let script = r#"
$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]
$wmi = Get-CimInstance Win32_Service | ForEach-Object { $_.Name }
$keys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue
foreach ($key in $keys) {
  $name = $key.PSChildName
  if ($wmi -notcontains $name) {
    $item = Get-ItemProperty $key.PSPath
    $rows.Add([pscustomobject]@{ name=$name; image_path=$item.ImagePath; start_mode=$item.Start; source='registry_only'; flag='hidden_service_candidate' })
  }
}
if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ name=''; image_path=''; start_mode=''; source='none_observed_or_unavailable'; flag='' }) }
$rows | Select-Object -First 500 | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn process_modules_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
foreach ($process in (Get-Process -ErrorAction SilentlyContinue | Select-Object -First 4096)) {
  try {
    foreach ($module in ($process.Modules | Select-Object -First 1024)) {
      if ($rows.Count -ge 50000) { break }
      $rows.Add([pscustomobject]@{
        pid=$process.Id; process=$process.ProcessName; module=$module.ModuleName;
        path=$module.FileName; base_address=('0x{0:x}' -f $module.BaseAddress.ToInt64());
        size=$module.ModuleMemorySize; company=$module.FileVersionInfo.CompanyName;
        file_version=$module.FileVersionInfo.FileVersion
      })
    }
  } catch {}
  if ($rows.Count -ge 50000) { break }
}
if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ pid=''; process=''; module=''; path=''; base_address=''; size=''; company=''; file_version='no_access_or_no_modules' }) }
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn process_threads_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
foreach ($process in (Get-Process -ErrorAction SilentlyContinue | Select-Object -First 4096)) {
  try {
    foreach ($thread in ($process.Threads | Select-Object -First 4096)) {
      if ($rows.Count -ge 50000) { break }
      $start = ''; $state = ''; $wait = ''
      try { $start = '0x{0:x}' -f $thread.StartAddress.ToInt64() } catch {}
      try { $state = [string]$thread.ThreadState } catch {}
      try { if ($state -eq 'Wait') { $wait = [string]$thread.WaitReason } } catch {}
      $rows.Add([pscustomobject]@{ pid=$process.Id; process=$process.ProcessName; thread_id=$thread.Id; start_address=$start; state=$state; wait_reason=$wait })
    }
  } catch {}
  if ($rows.Count -ge 50000) { break }
}
if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ pid=''; process=''; thread_id=''; start_address=''; state=''; wait_reason='no_access_or_no_threads' }) }
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn named_pipe_commands() -> CommandSpec {
    let script = r#"
$rows = @(Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Select-Object -First 20000 | ForEach-Object {
  [pscustomobject]@{ name=$_.Name; path=$_.FullName }
})
if ($rows.Count -eq 0) { $rows = @([pscustomobject]@{ name=''; path='no_access_or_no_named_pipes' }) }
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn smb_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
try {
  Get-SmbSession -ErrorAction Stop | Select-Object -First 20000 | ForEach-Object {
    $rows.Add([pscustomobject]@{ kind='session'; client=$_.ClientComputerName; user=$_.ClientUserName; path_or_share=''; id=$_.SessionId; detail="dialect=$($_.Dialect);opens=$($_.NumOpens)" })
  }
} catch {}
try {
  Get-SmbOpenFile -ErrorAction Stop | Select-Object -First 20000 | ForEach-Object {
    $rows.Add([pscustomobject]@{ kind='open_file'; client=$_.ClientComputerName; user=$_.ClientUserName; path_or_share=$_.Path; id=$_.FileId; detail="session=$($_.SessionId);share=$($_.ShareRelativePath)" })
  }
} catch {}
if ($rows.Count -eq 0) { $rows.Add([pscustomobject]@{ kind='none_observed_or_unavailable'; client=''; user=''; path_or_share=''; id=''; detail='' }) }
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn defender_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
try {
  $status = Get-MpComputerStatus -ErrorAction Stop
  foreach ($property in $status.PSObject.Properties) {
    if ($rows.Count -ge 2000) { break }
    $rows.Add([pscustomobject]@{ kind='status'; name=$property.Name; value="$($property.Value)"; source='Get-MpComputerStatus' })
  }
} catch { $rows.Add([pscustomobject]@{ kind='status_unavailable'; name=''; value=$_.Exception.Message; source='Get-MpComputerStatus' }) }
try {
  $preference = Get-MpPreference -ErrorAction Stop
  foreach ($name in @('ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress','DisableRealtimeMonitoring','DisableScriptScanning','PUAProtection','MAPSReporting','SubmitSamplesConsent')) {
    $value = $preference.$name
    $rows.Add([pscustomobject]@{ kind='preference'; name=$name; value=($value -join ' | '); source='Get-MpPreference' })
  }
} catch { $rows.Add([pscustomobject]@{ kind='preference_unavailable'; name=''; value=$_.Exception.Message; source='Get-MpPreference' }) }
try {
  Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 10000 | ForEach-Object {
    $rows.Add([pscustomobject]@{ kind='threat_detection'; name=$_.ThreatID; value="initial=$($_.InitialDetectionTime);last=$($_.LastThreatStatusChangeTime);resources=$($_.Resources -join ' | ')"; source='Get-MpThreatDetection' })
  }
} catch {}
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}
/// 仅网络上下文（供 export net 复用）：连接主表之外的 DNS 缓存/hosts/共享/防火墙。
pub fn collect_network(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_text_command(
        "dns_cache",
        &layout.dns_cache,
        DNS_CACHE_HEADER,
        &[dns_cache_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "dns_config",
        &layout.dns_config,
        DNS_CONFIG_HEADER,
        &[hosts_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "shares",
        &layout.shares,
        SHARES_HEADER,
        &[share_commands()],
        errors,
        false,
    )?;
    collect_text_command(
        "firewall_rules",
        &layout.firewall_rules,
        FIREWALL_HEADER,
        &[firewall_commands()],
        errors,
        false,
    )
}

fn driver_commands() -> CommandSpec {
    let script = r#"
Get-CimInstance Win32_SystemDriver |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='display_name';Expression={$_.DisplayName}},
    @{Name='pathname';Expression={$_.PathName}},
    @{Name='state';Expression={$_.State}},
    @{Name='start_mode';Expression={$_.StartMode}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn dns_cache_commands() -> CommandSpec {
    let script = r#"
Get-DnsClientCache |
  Select-Object @{Name='entry';Expression={$_.Entry}},
    @{Name='record_type';Expression={$_.Type}},
    @{Name='data';Expression={$_.Data}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn hosts_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hosts) {
  $lineNo = 0
  foreach ($line in Get-Content $hosts) {
    $lineNo++
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $parts = $trimmed -split '\s+'
    if ($parts.Count -ge 2) {
      $rows.Add([pscustomobject]@{ kind='hosts_entry'; source="$hosts`:$lineNo"; key=$parts[0]; value=($parts[1..($parts.Count-1)] -join ' ') })
    }
  }
}
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn share_commands() -> CommandSpec {
    let script = r#"
Get-SmbShare |
  Select-Object @{Name='name';Expression={$_.Name}},
    @{Name='path';Expression={$_.Path}},
    @{Name='description';Expression={$_.Description}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn firewall_commands() -> CommandSpec {
    let script = r#"
Get-NetFirewallRule -PolicyStore ActiveStore |
  Select-Object -First 4000 |
  Select-Object @{Name='display_name';Expression={$_.DisplayName}},
    @{Name='enabled';Expression={$_.Enabled}},
    @{Name='direction';Expression={$_.Direction}},
    @{Name='action';Expression={$_.Action}},
    @{Name='profile';Expression={$_.Profile}},
    @{Name='rule_text';Expression={"ID=$($_.Name) Group=$($_.Group)"}} |
  ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn hidden_account_commands() -> CommandSpec {
    let script = r#"
$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]
$samNames = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
$localUsers = @()
# SAM 用户名枚举需要 SYSTEM；普通权限失败时输出占位说明。
# reg.exe 在中文系统输出 GBK，PowerShell 已按 UTF-8 解码会破坏含中文的用户名，
# 导致隐藏账户比对失效；这里经 cmd.exe chcp 65001 让 reg 以 UTF-8 输出后再交给 PS。
$samQuery = cmd /c "chcp 65001>nul & reg query HKLM\SAM\SAM\Domains\Account\Users\Names" 2>$null
if ($LASTEXITCODE -eq 0 -and $samQuery) {
  foreach ($line in $samQuery) {
    $trimmed = ([string]$line).Trim()
    if ($trimmed -match '\\Names\\([^\\]+)$') {
      [void]$samNames.Add($Matches[1])
    }
  }
} else {
  $rows.Add([pscustomobject]@{ name=''; sid=''; flag='sam_unreadable_needs_system'; source='reg query failed' })
}
try {
  $localUsers = @(Get-LocalUser -ErrorAction Stop)
  foreach ($name in $samNames) {
    $local = $localUsers | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
    $flag = if ($null -eq $local) { 'sam_only_hidden_candidate' } else { 'sam_entry' }
    $sid = if ($null -eq $local) { '' } else { [string]$local.SID }
    $rows.Add([pscustomobject]@{ name=$name; sid=$sid; flag=$flag; source='HKLM\SAM\SAM\Domains\Account\Users\Names' })
  }
  foreach ($local in $localUsers) {
    $flag = if ($local.Name.EndsWith('$')) { 'dollar_suffix_hidden_candidate' } else { '' }
    $rows.Add([pscustomobject]@{ name=$local.Name; sid="$($local.SID)"; flag=$flag; source='Get-LocalUser' })
  }
} catch {
  $rows.Add([pscustomobject]@{ name=''; sid=''; flag='local_user_enumeration_failed'; source=$_.Exception.Message })
}
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}

fn ps_history_commands() -> CommandSpec {
    let script = r#"
$rows = New-Object System.Collections.Generic.List[object]
$historyFiles = @()
$historyFiles += ,"$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
  $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
  $historyFiles += ,$p
}
foreach ($file in $historyFiles) {
  if (Test-Path $file) {
    $user = if ($file -like "$env:APPDATA*") { [Environment]::UserName } else { ($file -split '\\')[2] }
    $lineNo = 0
    foreach ($line in (Get-Content $file | Select-Object -First 20000)) {
      $lineNo++
      if ($line.Trim() -ne '') {
        $rows.Add([pscustomobject]@{ user=$user; path=$file; line_no=$lineNo; command=$line.Trim() })
      }
    }
  }
}
$rows | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}
