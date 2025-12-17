$ErrorActionPreference = 'Stop'
$env:TECHNIQUE_ID = 'T1105'
$scriptLog = if ($env:SCRIPT_LOG) { $env:SCRIPT_LOG } else { "$(pwd)/artifacts/logs/T1105/$(Get-Date -UFormat %s).log" }

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('o')
    "[$($env:TECHNIQUE_ID)] $timestamp $Message" | Tee-Object -FilePath $scriptLog -Append
}

Write-Log "Starting ingress tool transfer demo (T1105)."
Write-Log "DRY_RUN=$($env:DRY_RUN)"

$tempPath = Join-Path -Path $env:TEMP -ChildPath "ttp-ingress-demo.txt"
$demoUrl = 'https://example.com/health'

if ($env:DRY_RUN -ne 'false') {
    Write-Log "Dry-run: would download $demoUrl to $tempPath"
} else {
    Write-Log "Downloading $demoUrl to $tempPath"
    Invoke-WebRequest -Uri $demoUrl -OutFile $tempPath
    Write-Log "Download complete. Remove file after validation."
}
