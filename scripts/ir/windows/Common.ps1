Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

function Initialize-IrOutput {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    [System.IO.Directory]::CreateDirectory($full) | Out-Null
    try {
        $acl = Get-Acl -LiteralPath $full
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $access = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($access)
        Set-Acl -LiteralPath $full -AclObject $acl
    } catch {
        Write-Warning "无法收紧输出目录 ACL: $($_.Exception.Message)"
    }
    $script:IrOutput = $full
    $script:IrStatus = Join-Path $full 'status.tsv'
    "module`tstarted_at`tfinished_at`texit_code`toutput" | Set-Content -LiteralPath $script:IrStatus -Encoding UTF8
    return $full
}

function Invoke-IrCapture {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [int]$MaxLines = 100000
    )
    $target = Join-Path $script:IrOutput ($Name + '.txt')
    $started = [DateTime]::UtcNow.ToString('o')
    $code = 0
    try {
        & $Script 2>&1 | Select-Object -First $MaxLines | Out-File -LiteralPath $target -Encoding UTF8 -Width 4096
        if (-not $?) { $code = 1 }
    } catch {
        $_ | Out-String | Out-File -LiteralPath $target -Encoding UTF8 -Append
        $code = 1
    }
    $finished = [DateTime]::UtcNow.ToString('o')
    "$Name`t$started`t$finished`t$code`t$target" | Add-Content -LiteralPath $script:IrStatus -Encoding UTF8
}

function Export-IrCsv {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$InputObject
    )
    $target = Join-Path $script:IrOutput ($Name + '.csv')
    try {
        @($InputObject) | Export-Csv -LiteralPath $target -NoTypeInformation -Encoding UTF8
    } catch {
        "error,$($_.Exception.Message)" | Set-Content -LiteralPath $target -Encoding UTF8
    }
}

function Copy-IrEvidenceFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Category,
        [long]$MaxFileBytes = 268435456
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return }
    try {
        $item = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
        if ($item.Length -gt $MaxFileBytes) {
            "$Source`t`t$($item.Length)`t`tskipped_size_limit" | Add-Content -LiteralPath $script:IrCopyStatus -Encoding UTF8
            return
        }
        if (($script:IrCopiedBytes + $item.Length) -gt $script:IrCopyBudgetBytes) {
            "$Source`t`t$($item.Length)`t`tskipped_total_limit" | Add-Content -LiteralPath $script:IrCopyStatus -Encoding UTF8
            return
        }
        $destinationDir = Join-Path $script:IrOutput (Join-Path 'evidence' $Category)
        [System.IO.Directory]::CreateDirectory($destinationDir) | Out-Null
        $safeName = ($Source -replace '^[A-Za-z]:', '') -replace '[\\/:*?"<>|]', '_'
        $destination = Join-Path $destinationDir $safeName
        try {
            Copy-Item -LiteralPath $Source -Destination $destination -Force -ErrorAction Stop
        } catch {
            if (Get-Command esentutl.exe -ErrorAction SilentlyContinue) {
                & esentutl.exe /y $Source /d $destination /o | Out-Null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $destination)) { throw }
            } else {
                throw
            }
        }
        $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        "$Source`t$destination`t$($item.Length)`t$hash`tcopied" | Add-Content -LiteralPath $script:IrCopyStatus -Encoding UTF8
        $script:IrCopiedBytes += $item.Length
    } catch {
        "$Source`t`t0`t`tcopy_failed: $($_.Exception.Message)" | Add-Content -LiteralPath $script:IrCopyStatus -Encoding UTF8
    }
}

function Initialize-IrCopyBudget {
    param([long]$MaxTotalBytes = 2147483648)
    $script:IrCopyBudgetBytes = $MaxTotalBytes
    $script:IrCopiedBytes = 0
    $script:IrCopyStatus = Join-Path $script:IrOutput 'evidence_copy_manifest.tsv'
    "source`tdestination_or_size`tsize_or_status`tsha256`tstatus" | Set-Content -LiteralPath $script:IrCopyStatus -Encoding UTF8
}

function Complete-IrOutput {
    $manifest = Join-Path $script:IrOutput 'SHA256SUMS.txt'
    Get-ChildItem -LiteralPath $script:IrOutput -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $manifest } |
        Sort-Object FullName |
        ForEach-Object {
            try {
                $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                "$hash  $($_.FullName.Substring($script:IrOutput.Length).TrimStart('\\'))"
            } catch {
                "HASH_ERROR  $($_.FullName)  $($_.Exception.Message)"
            }
        } | Set-Content -LiteralPath $manifest -Encoding UTF8
    Write-Host "完成: $script:IrOutput"
}
