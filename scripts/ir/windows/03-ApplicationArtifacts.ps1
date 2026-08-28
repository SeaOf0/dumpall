[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Output,
    [long]$MaxTotalBytes = 1073741824
)

Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Common.ps1')
[void](Initialize-IrOutput -Path $Output)
Initialize-IrCopyBudget -MaxTotalBytes $MaxTotalBytes

$metadata = @()
$copyNames = @('History', 'places.sqlite', 'downloads.sqlite', 'ConsoleHost_history.txt')
Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $profile = $_.FullName
    $profileName = $_.Name
    $roots = @(
        'AppData\Local\Google\Chrome\User Data',
        'AppData\Local\Microsoft\Edge\User Data',
        'AppData\Local\BraveSoftware\Brave-Browser\User Data',
        'AppData\Roaming\Mozilla\Firefox\Profiles',
        'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
    )
    foreach ($relative in $roots) {
        $root = Join-Path $profile $relative
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $copyNames -contains $_.Name } | Select-Object -First 2000 | ForEach-Object {
                Copy-IrEvidenceFile -Source $_.FullName -Category 'user_activity'
            }
    }
    $sensitiveMetadata = @(
        '.aws\config', '.aws\credentials', '.azure\azureProfile.json', '.kube\config',
        'AppData\Roaming\rclone\rclone.conf', 'AppData\Roaming\AnyDesk\service.conf',
        'AppData\Roaming\RustDesk\config\RustDesk2.toml', 'AppData\Roaming\TeamViewer\TeamViewer.ini'
    )
    foreach ($relative in $sensitiveMetadata) {
        $path = Join-Path $profile $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $item = Get-Item -LiteralPath $path -Force
                $hash = if ($item.Length -le 67108864) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
                $metadata += [pscustomobject]@{ User=$profileName; Path=$path; Length=$item.Length; LastWriteTimeUtc=$item.LastWriteTimeUtc; SHA256=$hash; ContentCopied=$false }
            } catch { }
        }
    }
}
Export-IrCsv -Name 'sensitive_application_metadata' -InputObject $metadata

Invoke-IrCapture -Name 'installed_remote_tools' -Script {
    Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|Atera|Mesh|VNC|Dameware' -or $_.PathName -match 'AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|Atera|Mesh|VNC|Dameware' }
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|Atera|Mesh|VNC|Dameware' } | Select-Object Id,Name,Path,StartTime
}
Invoke-IrCapture -Name 'docker' -Script { docker info; docker ps -a --no-trunc }
Invoke-IrCapture -Name 'containerd' -Script { ctr namespaces list; ctr containers list }
Invoke-IrCapture -Name 'wsl' -Script { wsl.exe --list --verbose }

Complete-IrOutput
