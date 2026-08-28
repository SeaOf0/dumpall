[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Output)

Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Common.ps1')
[void](Initialize-IrOutput -Path $Output)

Invoke-IrCapture -Name 'system' -Script { Get-ComputerInfo }
Invoke-IrCapture -Name 'processes' -Script {
    Get-CimInstance Win32_Process | ForEach-Object {
        $owner = try { Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop } catch { $null }
        [pscustomobject]@{
            ProcessId = $_.ProcessId; ParentProcessId = $_.ParentProcessId; Name = $_.Name
            ExecutablePath = $_.ExecutablePath; CommandLine = $_.CommandLine
            CreationDate = $_.CreationDate
            Owner = if ($owner -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { '' }
        }
    } | Format-List
}
Invoke-IrCapture -Name 'process_modules' -MaxLines 50000 -Script {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $process = $_
        try { $process.Modules | Select-Object @{n='PID';e={$process.Id}}, ModuleName, FileName, BaseAddress, ModuleMemorySize }
        catch { [pscustomobject]@{ PID=$process.Id; ModuleName='ACCESS_DENIED'; FileName=$_.Exception.Message } }
    } | Format-Table
}
Invoke-IrCapture -Name 'process_threads' -MaxLines 50000 -Script {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $process = $_
        try { $process.Threads | Select-Object @{n='PID';e={$process.Id}}, Id, StartAddress, ThreadState, WaitReason }
        catch { [pscustomobject]@{ PID=$process.Id; Id='ACCESS_DENIED'; StartAddress=$_.Exception.Message } }
    } | Format-Table
}
Invoke-IrCapture -Name 'tcp_connections' -Script { Get-NetTCPConnection | Sort-Object State,RemoteAddress,RemotePort }
Invoke-IrCapture -Name 'udp_endpoints' -Script { Get-NetUDPEndpoint | Sort-Object LocalAddress,LocalPort }
Invoke-IrCapture -Name 'network_config' -Script { Get-NetIPConfiguration -Detailed }
Invoke-IrCapture -Name 'routes' -Script { Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix }
Invoke-IrCapture -Name 'neighbors' -Script { Get-NetNeighbor | Sort-Object InterfaceIndex,IPAddress }
Invoke-IrCapture -Name 'dns_cache' -Script { Get-DnsClientCache }
Invoke-IrCapture -Name 'named_pipes' -MaxLines 20000 -Script { Get-ChildItem -Path '\\.\pipe\' | Select-Object FullName }
Invoke-IrCapture -Name 'smb_sessions' -Script { Get-SmbSession }
Invoke-IrCapture -Name 'smb_open_files' -Script { Get-SmbOpenFile }
Invoke-IrCapture -Name 'logged_on_users' -Script { Get-CimInstance Win32_LoggedOnUser }
Invoke-IrCapture -Name 'drivers' -Script { Get-CimInstance Win32_SystemDriver | Sort-Object State,Name }
Invoke-IrCapture -Name 'scheduled_tasks' -Script { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,Actions,Triggers,Principal }
Invoke-IrCapture -Name 'services' -Script { Get-CimInstance Win32_Service | Sort-Object State,Name }
Invoke-IrCapture -Name 'defender_status' -Script { Get-MpComputerStatus; Get-MpPreference }
Invoke-IrCapture -Name 'defender_threats' -Script { Get-MpThreat; Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending }
Invoke-IrCapture -Name 'firewall' -MaxLines 100000 -Script { Get-NetFirewallProfile; Get-NetFirewallRule | Where-Object Enabled -eq True }
Invoke-IrCapture -Name 'bits_jobs' -Script { Get-BitsTransfer -AllUsers }
Invoke-IrCapture -Name 'wmi_subscriptions' -Script {
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
    Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
    Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
}

Complete-IrOutput
