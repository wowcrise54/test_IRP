<#
.SYNOPSIS
Installs a Windows service that runs the specified executable.

.EXAMPLE
  .\install_service.ps1 -ServiceName "DemoService" -DisplayName "Demo Service" -ExecutablePath "C:\\Tools\\demo.exe"

.EXAMPLE
  .\install_service.ps1 -ServiceName "DemoService" -ExecutablePath "C:\\Tools\\demo.exe" -ArgumentList "--flag" -StartMode Automatic

.NOTES
  Remove with: Stop-Service -Name "<name>"; sc.exe delete "<name>"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [string]$ArgumentList = "",

    [string]$Description = "Custom persistence service",

    [ValidateSet("Automatic", "Manual", "Disabled")]
    [string]$StartMode = "Automatic"
)

if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    Write-Error "ExecutablePath '$ExecutablePath' does not exist."
    exit 1
}

if (-not $DisplayName) {
    $DisplayName = $ServiceName
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service '$ServiceName' already exists. Skipping creation."
    exit 0
}

$binaryPath = if ([string]::IsNullOrWhiteSpace($ArgumentList)) {
    "\"$ExecutablePath\""
} else {
    "\"$ExecutablePath\" $ArgumentList"
}

New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName $DisplayName -Description $Description -StartupType $StartMode

if ($StartMode -ne "Disabled") {
    Start-Service -Name $ServiceName
}

Write-Host "Service '$ServiceName' installed with startup mode '$StartMode'."
Write-Host "View it with: Get-Service -Name '$ServiceName'"
