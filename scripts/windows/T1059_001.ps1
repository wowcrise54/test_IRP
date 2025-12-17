$ErrorActionPreference = 'Stop'
$env:TECHNIQUE_ID = 'T1059_001'
$scriptLog = if ($env:SCRIPT_LOG) { $env:SCRIPT_LOG } else { "$(pwd)/artifacts/logs/T1059_001/$(Get-Date -UFormat %s).log" }

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('o')
    "[$($env:TECHNIQUE_ID)] $timestamp $Message" | Tee-Object -FilePath $scriptLog -Append
}

Write-Log "Starting PowerShell execution demo (T1059.001)."
Write-Log "DRY_RUN=$($env:DRY_RUN)"

if ($env:DRY_RUN -ne 'false') {
    Write-Log 'Dry-run mode enabled; demonstrating commands without side effects.'
    Write-Log "Current user: $(whoami)"
    Write-Log "PS version: $($PSVersionTable.PSVersion)"
} else {
    Write-Log 'Executing sample commands in lab mode.'
    whoami | Tee-Object -FilePath $scriptLog -Append
    Get-Process | Select-Object -First 3 | Tee-Object -FilePath $scriptLog -Append
    Write-Log 'Sample command execution completed.'
}
