<#
.SYNOPSIS
Registers a Scheduled Task that starts an executable or script using a chosen trigger.

.EXAMPLE
  .\create_scheduled_task.ps1 -TaskName "DemoTask" -ExecutablePath "C:\\Tools\\demo.exe" -Trigger AtLogOn

.EXAMPLE
  .\create_scheduled_task.ps1 -TaskName "SystemStartup" -ExecutablePath "C:\\Tools\\demo.exe" -Trigger AtStartup -SystemWide

.NOTES
  Remove with: Unregister-ScheduledTask -TaskName "<name>" -Confirm:$false
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TaskName,

    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [string]$ArgumentList = "",

    [ValidateSet("AtLogOn", "AtStartup", "Daily")]
    [string]$Trigger = "AtLogOn",

    [switch]$SystemWide
)

if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    Write-Error "ExecutablePath '$ExecutablePath' does not exist."
    exit 1
}

switch ($Trigger) {
    "AtStartup" { $triggerObj = New-ScheduledTaskTrigger -AtStartup }
    "Daily"    { $triggerObj = New-ScheduledTaskTrigger -Daily -At 6am }
    default     { $triggerObj = New-ScheduledTaskTrigger -AtLogOn }
}

$action = New-ScheduledTaskAction -Execute $ExecutablePath -Argument $ArgumentList

if ($SystemWide) {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
}

$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $triggerObj
Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

Write-Host "Scheduled task '$TaskName' registered with trigger '$Trigger'."
Write-Host "View it with: Get-ScheduledTask -TaskName '$TaskName'"
