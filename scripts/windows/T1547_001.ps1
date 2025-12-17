$ErrorActionPreference = 'Stop'
$env:TECHNIQUE_ID = 'T1547_001'
$scriptLog = if ($env:SCRIPT_LOG) { $env:SCRIPT_LOG } else { "$(pwd)/artifacts/logs/T1547_001/$(Get-Date -UFormat %s).log" }

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('o')
    "[$($env:TECHNIQUE_ID)] $timestamp $Message" | Tee-Object -FilePath $scriptLog -Append
}

Write-Log "Starting RunKey persistence demo (T1547.001)."
Write-Log "DRY_RUN=$($env:DRY_RUN)"

$runKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runKeyName = 'TTPDemoRunKey'
$runKeyValue = 'C:\\Windows\\System32\\notepad.exe'

if ($env:DRY_RUN -ne 'false') {
    Write-Log "Dry-run: would set RunKey $runKeyName with value $runKeyValue at $runKeyPath"
} else {
    Write-Log "Setting RunKey $runKeyName to $runKeyValue"
    New-Item -Path $runKeyPath -Force | Out-Null
    New-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runKeyValue -PropertyType String -Force | Out-Null
    Write-Log 'RunKey set. Remove with Remove-ItemProperty during cleanup.'
}
