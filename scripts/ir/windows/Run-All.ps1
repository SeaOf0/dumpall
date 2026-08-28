[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Output,
    [int]$Days = 7,
    [switch]$Parallel,
    [switch]$CollectUsn
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$fullOutput = [System.IO.Path]::GetFullPath($Output)
[System.IO.Directory]::CreateDirectory($fullOutput) | Out-Null
"started_at=$([DateTime]::UtcNow.ToString('o'))" | Set-Content -LiteralPath (Join-Path $fullOutput 'run_info.txt') -Encoding UTF8

& (Join-Path $PSScriptRoot '01-VolatileContext.ps1') -Output (Join-Path $fullOutput '01_volatile')

$canParallel = $false
if ($Parallel) {
    $system = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average
    $canParallel = ($system.TotalPhysicalMemory -ge 4GB -and $system.NumberOfLogicalProcessors -ge 4 -and $cpu.Average -lt 70)
}

if ($canParallel) {
    $forensicScript = Join-Path $PSScriptRoot '02-ForensicArtifacts.ps1'
    $applicationScript = Join-Path $PSScriptRoot '03-ApplicationArtifacts.ps1'
    $j1 = Start-Job -ScriptBlock {
        param($scriptPath,$out,$days,$collectUsn)
        if ($collectUsn) { & $scriptPath -Output $out -Days $days -CollectUsn }
        else { & $scriptPath -Output $out -Days $days }
    } -ArgumentList $forensicScript,(Join-Path $fullOutput '02_forensic'),$Days,[bool]$CollectUsn
    $j2 = Start-Job -ScriptBlock { param($scriptPath,$out) & $scriptPath -Output $out } -ArgumentList $applicationScript,(Join-Path $fullOutput '03_applications')
    @($j1,$j2) | Wait-Job | Receive-Job
    @($j1,$j2) | Remove-Job -Force -ErrorAction SilentlyContinue
    "parallel=2`nmodule_states=$($j1.State),$($j2.State)" | Add-Content -LiteralPath (Join-Path $fullOutput 'run_info.txt') -Encoding UTF8
} else {
    & (Join-Path $PSScriptRoot '02-ForensicArtifacts.ps1') -Output (Join-Path $fullOutput '02_forensic') -Days $Days -CollectUsn:$CollectUsn
    & (Join-Path $PSScriptRoot '03-ApplicationArtifacts.ps1') -Output (Join-Path $fullOutput '03_applications')
    'parallel=0' | Add-Content -LiteralPath (Join-Path $fullOutput 'run_info.txt') -Encoding UTF8
}

"finished_at=$([DateTime]::UtcNow.ToString('o'))" | Add-Content -LiteralPath (Join-Path $fullOutput 'run_info.txt') -Encoding UTF8
Get-ChildItem -LiteralPath $fullOutput -File -Recurse -Force | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
    try { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.FullName.Substring($fullOutput.Length).TrimStart('\\'))" } catch { "HASH_ERROR  $($_.FullName)" }
} | Set-Content -LiteralPath (Join-Path $fullOutput 'SHA256SUMS.txt') -Encoding UTF8
Write-Host "补充采集完成: $fullOutput"
