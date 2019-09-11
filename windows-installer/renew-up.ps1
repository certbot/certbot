function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }
$down = Join-Path (Get-ScriptDirectory) 'renew-down.ps1'
& $down

$taskName = "Certbot Renew Task"

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "certbot renew"'
$triggerAM = New-ScheduledTaskTrigger -Daily -At 12am
$triggerPM = New-ScheduledTaskTrigger -Daily -At 12pm
$principal = New-ScheduledTaskPrincipal -UserId 'System' -LogonType S4U -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $triggerAM,$triggerPM -TaskName $taskName -Description "Execute twice a day the 'certbot renew' command, to renew managed certificates if needed." -Principal $principal
