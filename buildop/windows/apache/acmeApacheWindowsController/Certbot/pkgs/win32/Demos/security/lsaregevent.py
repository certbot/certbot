import win32security, win32event
evt = win32event.CreateEvent(None,0,0,None)
win32security.LsaRegisterPolicyChangeNotification(win32security.PolicyNotifyAuditEventsInformation, evt)
print("Waiting for you change Audit policy in Management console ...")
ret_code=win32event.WaitForSingleObject(evt,1000000000)
## should come back when you change Audit policy in Management console ...
print(ret_code)
win32security.LsaUnregisterPolicyChangeNotification(win32security.PolicyNotifyAuditEventsInformation, evt)
