
Dim bindingip, port, debugFlag

bindingip = Wscript.Arguments.Item(0)
port = Wscript.Arguments.Item(1)
serverUrl = Wscript.Arguments.Item(2)
domain = Wscript.Arguments.Item(3)
emailaddr = Wscript.Arguments.Item(4)

WScript.echo "bindingip: "+bindingip
WScript.echo "port: "+port
'WScript.echo "serverUrl: "+serverUrl
WScript.echo "domain: "+domain
WScript.echo "email: "+emailaddr

If bindingip = "" Then
	WScript.echo "ERROR: Binding IP was found to be invalid"
	WScript.Quit(1)
End If

If port = "" Then
	WScript.echo "ERROR: Binding port was found to be invalid"
	WScript.Quit(2)
End If

CheckIfHostPortBoundToApacheSite bindingip, port

Function CheckIfHostPortBoundToApacheSite(host, port)

	Wscript.echo "Inside apache process"
	Dim objWMIService, pathToVersion, colItems,objItem, pid, shell, currentDir, confPath, isSuccess

	CheckIfApacheProcessRunning = ""
	isSuccess = ""
	pid = getPID(host, port)
	
	On Error Resume Next
	
	Set objWMIService = GetObject("winmgmts:\\" & host & "\root\cimv2") 
	Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Service Where ProcessId='" & pid & "' AND Started=true")
	
	commandLine=""
		
	For Each objItem in colItems
		WScript.echo "DEBUG: Process Executable Path: " + objItem.PathName	
		WScript.echo "DEBUG: Process command line: " + objItem.PathName	
		cmdLine = objItem.PathName	
		excutablePath = objItem.PathName
	Next
	
	Dim commandLineOptionRegex
	Set commandLineOptionRegex = new regexp
	commandLineOptionRegex.Global=true
	commandLineOptionRegex.Pattern = "-k(.*?)"
	commandLineOptionRegex.IgnoreCase=false

	'Check if process was started with -c option specifying configuration path
	If commandLineOptionRegex.Test(cmdLine) Then
		WScript.echo "DEBUG: configuration path -c found in cmdLine"
			cmE = Split(cmdLine,"-k")
			confPath = LTrim(cme(1))	
		WScript.echo "DEBUG: configuration path : "+confPath	
	Else
	   Wscript.echo "DEBUG: Cannot find -k option in cmdLine"
	End if
	'Get the executable path and add /conf for config path
	Dim serverRoot, exePath
	
		If InStr(1, excutablePath, """") = 1 Then
			exePath = """"+Split(excutablePath,"""")(1)+""""
		Else
			exePath = Split(excutablePath," ")(0)
		End If
	
	
		If InStr(cmdLine, " -d ") = 0 Then
			serverRoot = Split(Split(cmdLine,"-d ")(1)," ")(0)
			Wscript.echo "Service ServerRoot:"& serverRoot
		End If
		'if Len(serverRoot) = 0 Then
		'	'Get the server root from the command
		'	Dim objArguments
		'	Set objShell = WScript.CreateObject("WScript.Shell")
		'	Set objArguments = Wscript.Arguments
		'	Set objShell = WScript.CreateObject("WScript.Shell")
		'	Set objExecObject = objShell.Exec(exePath+" -S")
		'	Do While Not objExecObject.StdOut.AtEndOfStream
		'		strText = objExecObject.StdOut.ReadLine()
		'		if InStr(1,strText,"ServerRoot: ") = 1 Then
		'			serverRoot = Split(strText,"ServerRoot: ")(1)
		'			Wscript.Echo "Command ServerRoot:"& serverRoot    
		'		End If
		'	Loop
		'End If
		
		if Len(serverRoot) = 0 Then
			s = Split(excutablePath,"bin\httpd.exe")
		
		If InStr(s(0), """") = 0 Then
			serverRoot = s(0)+""
		else
			serverRoot = s(0)+""""
		End If
		End If
		serverRoot=Replace(serverRoot,"""","")
		serverRoot=Replace(serverRoot,"\","/")
		confPath=serverRoot+"/conf"		
		Wscript.echo "Apache ServerRoot path :"+serverRoot
		exePath=Replace(exePath,"""","")
		exePath=Replace(exePath,"\","/")
		Wscript.echo "Apache Executable path :"+exePath
		
		Dim oFSO, oExec
		Set oFSO = CreateObject("Scripting.FileSystemObject")
		if(Not oFSO.FolderExists(confPath)) Then
		confPath=serverRoot		
		End If
		
		If(oFSO.fileExists(exePath)) Then 
			
			Set shell = createobject("Wscript.shell")
			currentDir = shell.CurrentDirectory
			Wscript.echo "current directory  "+currentDir
			Dim errLog,outLog,cmdToExec,outLogText,errLogText
			errLog=""+currentDir+"\error.log"
			outLog=""+currentDir+"\output.log"
		
			
			certbotCmd = "cmd /C ""pushd """+serverRoot+""" & """+currentDir+"\Python\python.exe"" """+currentDir+"\bin\certbot.exe"" -a certbot-apache-win:apache_win -i certbot-apache-win:apache_win --server "+serverUrl+" --certbot-apache-win:apache_win-ctl """+ exePath +""" --certbot-apache-win:apache_win-server-root """+serverRoot+""" --certbot-apache-win:apache_win-challenge-location """+confPath+""" --force-renew --agree-tos -m "+emailaddr+" --expand -d "+domain+" --no-verify-ssl --no-redirect --no-autorenew -n & popd"" 2>"""+errLog+""" 1>"""+outLog+""""
			
			If InStr(domain, "*.") =1  Then
				certbotCmd = "cmd /C ""pushd """+serverRoot+""" &( echo. | """+currentDir+"\Python\python.exe"" """+currentDir+"\bin\certbot.exe"" -a certbot-apache-win:apache_win -i certbot-apache-win:apache_win --server "+serverUrl+" --certbot-apache-win:apache_win-ctl """+ exePath +""" --certbot-apache-win:apache_win-server-root """+serverRoot+""" --certbot-apache-win:apache_win-challenge-location """+confPath+""" --force-renew --agree-tos -m "+emailaddr+" --expand -d "+domain+" --no-verify-ssl --no-redirect --no-autorenew --authenticator manual --preferred-challenges dns --manual-auth-hook """+currentDir+"\dummydns.bat"" --manual-public-ip-logging-ok ) & popd"" 2>"""+errLog+""" 1>"""+outLog+""""
			End If
			
			
			Wscript.echo"Command to execute: "+certbotCmd
			cmdToExec = ""+currentDir+"\execute.cmd"
			Wscript.echo "File to execute:"+ cmdToExec
			Set objFileToWrite = CreateObject("Scripting.FileSystemObject").OpenTextFile(cmdToExec,2,true,-2)
			objFileToWrite.WriteLine(certbotCmd)
			objFileToWrite.Close
			Set objFileToWrite = Nothing	       	
			
			Set shellObj = shell.Exec(cmdToExec)
			Wscript.echo "Waiting for execution to complete"
			Do While shellObj.Status = 0
				WScript.Sleep 1000
			Loop
			
			Set objFileToRead = CreateObject("Scripting.FileSystemObject").OpenTextFile(outLog,1)
			outLogText = objFileToRead.ReadAll()
			objFileToRead.Close
			Set objFileToRead = Nothing
			If InStr(outLogText,"Congratulations! You have successfully enabled") > 0 Then
				isSuccess = true
			End If
			If InStr(outLogText,"Your existing certificate has been successfully renewed") > 0 Then
				isSuccess = true
			End If
			
			if (isSuccess = true) Then
				Wscript.echo "Installation Succesfull!!!"
			Else
				Set objFileToRead = CreateObject("Scripting.FileSystemObject").OpenTextFile(errLog,1)
				errLogText = objFileToRead.ReadAll()
				objFileToRead.Close
				Set objFileToRead = Nothing
				Wscript.echo errLogText
				Wscript.Quit(2)	
			End if
		CheckIfApacheProcessRunning = 1
	
	End if	
	If IsNull(objWMIService) Then
		WScript.echo "ERROR: Error accessing WMI service"
		Set objWMIService = Nothing
		WScript.Quit(5)
	End If
		
End Function

Function getPID(host, port)

	Set objShell = WScript.CreateObject("WScript.Shell")
	If IsNull(objShell) Then
		Set oReg = Nothing
		Set FileObj = Nothing
		Set WshShell = Nothing
		WScript.echo "DEBUG: An error occurred while accessing the Shell object"
		WScript.Quit(1)
	End If
	
	Set objExec = objShell.Exec("netstat -ano -p tcp")
	Dim opdata(5)
	strOut = ""
	PID = ""
	Do While Not objExec.StdOut.AtEndOfStream
		strOut = objExec.StdOut.ReadLine()
		If InStr(strOut,"LISTENING") > 0 Then
			op = Split(strOut, " ")
			ds = 0
			For each x in op
				If Len(x) > 0 Then
					opdata(ds) = x
					ds = ds + 1
				End If
			Next
			ipportdata = Split(opdata(1), ":")
			If StrComp(ipportdata(1),port) = 0 Then
				PID = opdata(4)
			End If
		End If
	Loop

	Set objShell = Nothing
	Set objExec = Nothing
	
	If Len(PID) = 0 Then
		WScript.echo "DEBUG: No application running on this host and port"
		WScript.Quit(255)
	End If
	getPID = PID

End Function
