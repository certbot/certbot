$taskName = "Certbot Renew Task"

$exists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
if ($exists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
