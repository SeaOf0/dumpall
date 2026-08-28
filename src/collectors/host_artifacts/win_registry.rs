//! Windows 注册表持久化采集：通过 PowerShell 只读查询常见持久化位置，
//! 输出统一的 registry_persistence.csv。覆盖手册与 Sysinternals Autoruns 的核心项：
//! Run/RunOnce（含 Wow6432Node）、Winlogon、AppInit、AppCert、IFEO、LSA、
//! 打印监控驱动、Netsh helper、Winsock NSP、网络提供程序顺序、屏幕保护、
//! StartupApproved、cmd AutoRun、AlwaysInstallElevated、pathext。

use crate::error::Result;
use crate::model::CollectionError;
use crate::output::paths::OutputLayout;

use crate::collectors::command::{collect_text_command, CommandSpec};

const HEADER: &str = "category,hive,path,name,value,flag\r\n";

pub fn collect(layout: &OutputLayout, errors: &mut Vec<CollectionError>) -> Result<()> {
    collect_text_command(
        "registry_persistence",
        &layout.registry_persistence,
        HEADER,
        &[registry_commands()],
        errors,
        false,
    )
}

fn registry_commands() -> CommandSpec {
    let script = r#"
$ErrorActionPreference = 'Stop'
$rows = New-Object System.Collections.Generic.List[object]
function Add-Row([string]$category, [string]$hive, [string]$path, [string]$name, [string]$value, [string]$flag) {
  if ($null -ne $value -and "$value" -ne '') {
    $rows.Add([pscustomobject]@{ category=$category; hive=$hive; path=$path; name=$name; value="$value"; flag=$flag })
  }
}
function Add-ValueRows([string]$category, [string[]]$keys, [string]$flag) {
  foreach ($key in $keys) {
    if (Test-Path $key) {
      $item = Get-ItemProperty -Path $key
      foreach ($prop in $item.PSObject.Properties) {
        if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
          Add-Row $category (Split-Path (Split-Path $key -Parent) -Leaf) $key $prop.Name ($prop.Value -join ' ') $flag
        }
      }
    }
  }
}
# --- Run / RunOnce（HKLM/HKCU + Wow6432Node + 所有已加载用户 hive）---
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
Add-ValueRows 'run_key' $runKeys ''
Get-ChildItem 'Registry::HKEY_USERS' | ForEach-Object {
  $user = $_.PSChildName
  foreach ($leaf in @('Run','RunOnce')) {
    $key = "Registry::HKEY_USERS\$user\SOFTWARE\Microsoft\Windows\CurrentVersion\$leaf"
    if (Test-Path $key) { Add-ValueRows 'run_key_user_hive' @($key) "user=$user" }
  }
}
# --- Winlogon ---
Add-ValueRows 'winlogon' @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') ''
# --- AppInit DLLs ---
Add-ValueRows 'appinit' @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows') ''
# --- AppCert DLLs ---
Add-ValueRows 'appcert' @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls') ''
# --- IFEO（含 Debugger / 全局标志）---
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
  $image = $_.PSChildName
  $item = Get-ItemProperty $_.PSPath
  foreach ($prop in $item.PSObject.Properties) {
    if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
      Add-Row 'ifeo' 'HKLM' $_.PSPath $prop.Name "$($prop.Value)" "image=$image"
    }
  }
  $silent = Join-Path $_.PSPath 'SilentProcessExit'
  if (Test-Path $silent) { Add-ValueRows 'ifeo_silent_process_exit' @($silent) "image=$image" }
}
# --- LSA 通知/安全包 ---
Add-ValueRows 'lsa' @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa') ''
# --- 打印监控驱动 ---
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
  $monitor = $_.PSChildName
  $item = Get-ItemProperty $_.PSPath
  if ($item.Driver) { Add-Row 'print_monitor' 'HKLM' $_.PSPath 'Driver' $item.Driver "monitor=$monitor" }
}
# --- Netsh helper ---
Add-ValueRows 'netsh_helper' @('HKLM:\SOFTWARE\Microsoft\Netsh') ''
# --- Winsock 命名空间目录 ---
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries' -ErrorAction SilentlyContinue | ForEach-Object {
  $item = Get-ItemProperty $_.PSPath
  if ($item.LibraryPath) { Add-Row 'winsock_nsp' 'HKLM' $_.PSPath 'LibraryPath' $item.LibraryPath '' }
}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64' -ErrorAction SilentlyContinue | ForEach-Object {
  $item = Get-ItemProperty $_.PSPath
  if ($item.LibraryPath) { Add-Row 'winsock_nsp' 'HKLM' $_.PSPath 'LibraryPath' $item.LibraryPath '' }
}
# --- 网络提供程序顺序 ---
Add-ValueRows 'network_provider' @('HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order') ''
# --- 屏幕保护 ---
Add-ValueRows 'screensaver' @('HKCU:\Control Panel\Desktop') 'scrnsave'
# --- 启动文件夹批准状态 ---
Add-ValueRows 'startup_approved' @(
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
) ''
# --- cmd AutoRun ---
Add-ValueRows 'cmd_autorun' @(
  'HKCU:\Software\Microsoft\Command Processor',
  'HKLM:\SOFTWARE\Microsoft\Command Processor'
) ''
# --- AlwaysInstallElevated ---
Add-ValueRows 'always_install_elevated' @(
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer',
  'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
) ''
# --- PATHEXT 劫持面 ---
$envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
if (Test-Path $envKey) {
  $item = Get-ItemProperty $envKey
  if ($item.PATHEXT) { Add-Row 'pathext' 'HKLM' $envKey 'PATHEXT' $item.PATHEXT '' }
}
# --- RDP 客户端连接历史（MRU）---
Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue | ForEach-Object {
  $server = $_.PSChildName
  $item = Get-ItemProperty (Join-Path $_.PSPath 'UsernameHint') -ErrorAction SilentlyContinue
  Add-Row 'rdp_client_mru' 'HKCU' $_.PSPath 'UsernameHint' $item.UsernameHint "server=$server"
}
# --- 机器级与用户级环境变量全量 ---
foreach ($scope in @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'HKCU:\Environment')) {
  if (Test-Path $scope) {
    $item = Get-ItemProperty $scope
    foreach ($prop in $item.PSObject.Properties) {
      if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
        Add-Row 'environment_variable' (Split-Path (Split-Path $scope -Parent) -Leaf) $scope $prop.Name "$($prop.Value)" ''
      }
    }
  }
}
# --- 辅助功能劫持（sethc/osk/narrator 替换）---
foreach ($app in @('sethc.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe')) {
  $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$app"
  if (Test-Path $key) {
    $item = Get-ItemProperty $key
    if ($item.Debugger) { Add-Row 'accessibility_hijack' 'HKLM' $key 'Debugger' $item.Debugger "app=$app" }
  }
}
$rows | Sort-Object category, path, name | ConvertTo-Csv -NoTypeInformation
"#;
    CommandSpec::powershell(script)
}
