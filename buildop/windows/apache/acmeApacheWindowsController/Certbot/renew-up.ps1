function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }
$down = Join-Path (Get-ScriptDirectory) 'renew-down.ps1'
& $down

$taskName = "Certbot Renew Task"

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "certbot renew"'
$delay = New-TimeSpan -Hours 12
$triggerAM = New-ScheduledTaskTrigger -Daily -At 12am -RandomDelay $delay
$triggerPM = New-ScheduledTaskTrigger -Daily -At 12pm -RandomDelay $delay
# NB: For now scheduled task is set up under Administrators group account because Certbot Installer installs Certbot for all users.
# If in the future we allow the Installer to install Certbot for one specific user, the scheduled task will need to
# switch to this user, since Certbot will be available only for him.
$adminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminsGroupID = $adminsSID.Translate([System.Security.Principal.NTAccount]).Value
$principal = New-ScheduledTaskPrincipal -GroupId $adminsGroupID -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $triggerAM,$triggerPM -TaskName $taskName -Description "Execute twice a day the 'certbot renew' command, to renew managed certificates if needed." -Principal $principal
