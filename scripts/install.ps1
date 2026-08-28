$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Architecture = $env:PROCESSOR_ARCHITECTURE
if ($Architecture -eq "AMD64") {
    $Binary = "dumpall-windows-amd64.exe"
} elseif ($Architecture -eq "x86") {
    $Binary = "dumpall-windows-x86.exe"
} elseif ($Architecture -eq "ARM64") {
    $Binary = "dumpall-windows-arm64.exe"
} else {
    throw "不支持的 Windows 架构: $Architecture"
}

$Source = Join-Path $Root "bin\$Binary"
if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw "缺少匹配的发布文件: $Source"
}

$Destination = Join-Path $env:LOCALAPPDATA "dumpall"
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$DestinationFile = Join-Path $Destination "dumpall.exe"
if (Test-Path -LiteralPath $DestinationFile -PathType Leaf) {
    throw "目标已存在，未覆盖: $DestinationFile"
}
Copy-Item -LiteralPath $Source -Destination $DestinationFile
Write-Output ("已安装: " + $DestinationFile)
