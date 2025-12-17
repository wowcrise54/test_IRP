<#
.SYNOPSIS
Adds an entry to the Windows Run registry key for persistence.

.EXAMPLE
  .\add_run_key.ps1 -EntryName "DemoRun" -ExecutablePath "C:\\Tools\\demo.exe"

.EXAMPLE
  .\add_run_key.ps1 -EntryName "SystemWide" -ExecutablePath "C:\\Tools\\demo.exe" -Scope LocalMachine

.NOTES
  Remove with: Remove-ItemProperty -Path <RunKeyPath> -Name "<EntryName>"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$EntryName,

    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$Scope = "CurrentUser",

    [string]$ArgumentList = ""
)

if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    Write-Error "ExecutablePath '$ExecutablePath' does not exist."
    exit 1
}

$basePath = if ($Scope -eq "LocalMachine") {
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
} else {
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
}

if (-not (Test-Path -Path $basePath)) {
    New-Item -Path $basePath -Force | Out-Null
}

$value = if ([string]::IsNullOrWhiteSpace($ArgumentList)) {
    $ExecutablePath
} else {
    "\"$ExecutablePath\" $ArgumentList"
}

Set-ItemProperty -Path $basePath -Name $EntryName -Value $value

Write-Host "Registry Run entry '$EntryName' created under $basePath"
Write-Host "Verify with: Get-ItemProperty -Path $basePath | Select-Object $EntryName"
