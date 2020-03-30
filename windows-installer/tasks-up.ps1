#Requires -Version 5.0
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]
    $InstallDir
)

function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }
$down = Join-Path (Get-ScriptDirectory) 'tasks-down.ps1'
& $down

$taskName = "Certbot Renew and Auto-Update Task"
$taskDescription = "Execute twice a day the 'certbot renew' command, to renew managed certificates if needed, and upgrade Certbot is a new version is available."

$actionRenew = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command ""& '$InstallDir\bin\certbot.exe' renew"""
$actionUpgrade = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -File ""$InstallDir\auto-update.ps1"""

$delay = New-TimeSpan -Hours 12
$triggerAM = New-ScheduledTaskTrigger -Daily -At 12am -RandomDelay $delay
$triggerPM = New-ScheduledTaskTrigger -Daily -At 12pm -RandomDelay $delay
# NB: For now scheduled task is set up under Administrators account because Certbot Installer installs Certbot for all users.
# If in the future we allow the Installer to install Certbot for one specific user, the scheduled task will need to
# switch to this user, since Certbot will be available only for him.
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroupID = $adminSID.Translate([System.Security.Principal.NTAccount]).Value
$principal = New-ScheduledTaskPrincipal -GroupId $adminGroupID -RunLevel Highest
Register-ScheduledTask -Action $actionRenew, $actionUpgrade -Trigger $triggerAM, $triggerPM -TaskName $taskName -Description $taskDescription -Principal $principal
