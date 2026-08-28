[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Output,
    [int]$Days = 7,
    [int]$MaxFiles = 20000,
    [long]$MaxTotalBytes = 2147483648,
    [switch]$CollectUsn
)

Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Common.ps1')
[void](Initialize-IrOutput -Path $Output)
Initialize-IrCopyBudget -MaxTotalBytes $MaxTotalBytes
if ($Days -lt 1 -or $MaxFiles -lt 1) { throw 'Days 和 MaxFiles 必须是正整数' }

Invoke-IrCapture -Name 'usn_journal_metadata' -Script { fsutil usn queryjournal $env:SystemDrive }
if ($CollectUsn) {
    Invoke-IrCapture -Name 'usn_journal_records' -MaxLines 50000 -Script {
        fsutil usn readjournal $env:SystemDrive csv | Select-Object -First 50000
    }
}
Invoke-IrCapture -Name 'shadow_copies' -Script { Get-CimInstance Win32_ShadowCopy }
Invoke-IrCapture -Name 'restore_points' -Script { Get-ComputerRestorePoint }
Invoke-IrCapture -Name 'event_log_configuration' -Script { wevtutil el | ForEach-Object { wevtutil gl $_ } }
Invoke-IrCapture -Name 'logon_sessions' -Script { Get-CimInstance Win32_LogonSession | Sort-Object StartTime -Descending }

$fixed = @(
    @{ Path = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"; Category = 'execution' },
    @{ Path = "$env:SystemRoot\System32\sru\SRUDB.dat"; Category = 'execution' },
    @{ Path = "$env:SystemRoot\System32\LogFiles\Sum\Current.mdb"; Category = 'execution' },
    @{ Path = "$env:SystemRoot\INF\setupapi.dev.log"; Category = 'devices' },
    @{ Path = "$env:SystemRoot\System32\drivers\etc\hosts"; Category = 'network' }
)
foreach ($entry in $fixed) { Copy-IrEvidenceFile -Source $entry.Path -Category $entry.Category }

$roots = @(
    @{ Path = "$env:SystemRoot\Prefetch"; Category = 'prefetch'; Filter = '*.pf' },
    @{ Path = "$env:SystemRoot\System32\winevt\Logs"; Category = 'event_logs'; Filter = '*.evtx' },
    @{ Path = "$env:SystemRoot\System32\Tasks"; Category = 'tasks'; Filter = '*' },
    @{ Path = "$env:SystemRoot\appcompat\pca"; Category = 'execution'; Filter = '*' },
    @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"; Category = 'wer'; Filter = '*.wer' },
    @{ Path = "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"; Category = 'wer'; Filter = '*.wer' },
    @{ Path = "$env:ProgramData\Microsoft\Windows Defender\Support"; Category = 'defender'; Filter = '*' },
    @{ Path = "$env:SystemRoot\System32\LogFiles\Firewall"; Category = 'firewall'; Filter = '*.log' }
)
$copied = 0
foreach ($root in $roots) {
    if ($copied -ge $MaxFiles) { break }
    if (-not (Test-Path -LiteralPath $root.Path)) { continue }
    Get-ChildItem -LiteralPath $root.Path -File -Recurse -Force -Filter $root.Filter -ErrorAction SilentlyContinue |
        Select-Object -First ($MaxFiles - $copied) |
        ForEach-Object { Copy-IrEvidenceFile -Source $_.FullName -Category $root.Category; $copied++ }
}

$activity = @()
Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $profile = $_.FullName
    $candidates = @(
        @{ Relative = 'NTUSER.DAT'; Category = 'user_hives' },
        @{ Relative = 'AppData\Local\Microsoft\Windows\UsrClass.dat'; Category = 'user_hives' },
        @{ Relative = 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'; Category = 'jump_lists' },
        @{ Relative = 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'; Category = 'jump_lists' },
        @{ Relative = 'AppData\Roaming\Microsoft\Windows\Recent'; Category = 'lnk' },
        @{ Relative = 'AppData\Local\Microsoft\Terminal Server Client\Cache'; Category = 'rdp_cache' },
        @{ Relative = 'AppData\Local\ConnectedDevicesPlatform'; Category = 'activities' }
    )
    foreach ($candidate in $candidates) {
        $path = Join-Path $profile $candidate.Relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Copy-IrEvidenceFile -Source $path -Category $candidate.Category
        } elseif (Test-Path -LiteralPath $path -PathType Container) {
            Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue |
                Select-Object -First 2000 | ForEach-Object { Copy-IrEvidenceFile -Source $_.FullName -Category $candidate.Category }
        }
    }
    $activity += Get-ChildItem -LiteralPath $profile -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge [DateTime]::UtcNow.AddDays(-$Days) } |
        Select-Object -First 5000 FullName,Length,CreationTimeUtc,LastWriteTimeUtc,LastAccessTimeUtc,Attributes
}
Export-IrCsv -Name 'recent_user_files' -InputObject ($activity | Select-Object -First 50000)

Complete-IrOutput
