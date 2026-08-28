[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Output,
    [Parameter(Mandatory = $true)][Alias('Pid')][int[]]$ProcessId,
    [switch]$CaptureDump,
    [string]$ProcDumpPath,
    [switch]$AllowUnsignedTool,
    [int]$MinFreeGB = 4
)

Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Common.ps1')
[void](Initialize-IrOutput -Path $Output)

if ($CaptureDump) {
    if (-not $ProcDumpPath -or -not (Test-Path -LiteralPath $ProcDumpPath -PathType Leaf)) { throw 'CaptureDump 需要有效的 ProcDumpPath' }
    $signature = Get-AuthenticodeSignature -LiteralPath $ProcDumpPath
    if (-not $AllowUnsignedTool -and $signature.Status -ne 'Valid') { throw "ProcDump 签名无效: $($signature.Status)" }
    $toolHash = (Get-FileHash -LiteralPath $ProcDumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "path=$ProcDumpPath`nsha256=$toolHash`nsignature=$($signature.Status)" | Set-Content -LiteralPath (Join-Path $script:IrOutput 'memory_tool.txt') -Encoding UTF8
}

foreach ($targetPid in ($ProcessId | Sort-Object -Unique)) {
    if ($targetPid -le 0) { continue }
    $pidDir = Join-Path $script:IrOutput ("pid_" + $targetPid)
    [System.IO.Directory]::CreateDirectory($pidDir) | Out-Null
    try {
        Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -ErrorAction Stop |
            Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate |
            Export-Csv -LiteralPath (Join-Path $pidDir 'process.csv') -NoTypeInformation -Encoding UTF8
        $process = Get-Process -Id $targetPid -ErrorAction Stop
        try { $process.Modules | Select-Object ModuleName,FileName,BaseAddress,ModuleMemorySize | Export-Csv -LiteralPath (Join-Path $pidDir 'modules.csv') -NoTypeInformation -Encoding UTF8 } catch { $_ | Out-File (Join-Path $pidDir 'modules_error.txt') }
        try { $process.Threads | Select-Object Id,StartAddress,ThreadState,WaitReason | Export-Csv -LiteralPath (Join-Path $pidDir 'threads.csv') -NoTypeInformation -Encoding UTF8 } catch { $_ | Out-File (Join-Path $pidDir 'threads_error.txt') }
    } catch {
        $_ | Out-File -LiteralPath (Join-Path $pidDir 'process_error.txt') -Encoding UTF8
        continue
    }
    if (-not $CaptureDump) { continue }
    $drive = Get-PSDrive -Name ([System.IO.Path]::GetPathRoot($script:IrOutput).Substring(0,1))
    if ($drive.Free -lt ($MinFreeGB * 1GB)) {
        'skipped: insufficient free space' | Set-Content -LiteralPath (Join-Path $pidDir 'dump_status.txt') -Encoding UTF8
        continue
    }
    $dump = Join-Path $pidDir ("process_" + $targetPid + '.dmp')
    $arguments = @('-accepteula', '-ma', $targetPid, ('"{0}"' -f $dump.Replace('"', '""')))
    $job = Start-Process -FilePath $ProcDumpPath -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if (-not $job.WaitForExit(300000)) {
        try { $job.Kill() } catch { }
        'timeout after 300 seconds' | Set-Content -LiteralPath (Join-Path $pidDir 'dump_status.txt') -Encoding UTF8
    } else {
        "exit_code=$($job.ExitCode)" | Set-Content -LiteralPath (Join-Path $pidDir 'dump_status.txt') -Encoding UTF8
        if (Test-Path -LiteralPath $dump) { Get-FileHash -LiteralPath $dump -Algorithm SHA256 | Format-List | Out-File -LiteralPath (Join-Path $pidDir 'dump_sha256.txt') -Encoding UTF8 }
    }
}

Complete-IrOutput
