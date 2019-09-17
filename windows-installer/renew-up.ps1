param(
    [string]$userLevel = "AllUsers"
)

function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }
$down = Join-Path (Get-ScriptDirectory) 'renew-down.ps1'
& $down

$taskName = "Certbot Renew Task"

if ($userLevel -eq "CurrentUser") {
    $taskUser = $env:UserName
} else {
    $taskUser = "SYSTEM"
}

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "certbot renew"'
$delay = New-TimeSpan -Hours 12
$triggerAM = New-ScheduledTaskTrigger -Daily -At 12am -RandomDelay $delay
$triggerPM = New-ScheduledTaskTrigger -Daily -At 12pm -RandomDelay $delay
$principal = New-ScheduledTaskPrincipal -UserId $taskUser -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $triggerAM,$triggerPM -TaskName $taskName -Description "Execute twice a day the 'certbot renew' command, to renew managed certificates if needed." -Principal $principal
