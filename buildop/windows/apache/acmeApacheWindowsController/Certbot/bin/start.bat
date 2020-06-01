@echo off
set certbotfolder="%windir:~0,3%Certbot"
echo checking folder exists %certbotfolder%
if exist %certbotfolder% (
     echo taking ownership of %certbotfolder%
     takeown /f %certbotfolder% /R /D N
     echo granting access to %certbotfolder% for administrators
     icacls %certbotfolder% /t /grant Administrators:F
     icacls %certbotfolder% /t /grant Everyone:RX
	 icacls %certbotfolder% /l /t /grant Everyone:RX
) else (
     echo certbot directory does not exist. No need to update permissions.
)
pushd %~dp0
cscript.exe //nologo ./findApachePath.vbs %*
popd

