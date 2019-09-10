$taskName = "Certbot Renew Task"

$exists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
if ($exists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "certbot renew"'
$triggerAM = New-ScheduledTaskTrigger -Daily -At 12am
$triggerPM = New-ScheduledTaskTrigger -Daily -At 12pm
$principal = New-ScheduledTaskPrincipal -UserId $env:UserName -LogonType S4U -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $triggerAM,$triggerPM -TaskName $taskName -Description "Execute twice a day the 'certbot renew' command, to renew managed certificates if needed." -Principal $principal
