@echo off
set certbotfolder="%windir:~0,3%Certbot"
echo checking folder exists %certbotfolder%
pushd %~dp0

if exist %certbotfolder% (
     echo taking ownership of %certbotfolder%
     rem takeown /f %certbotfolder% /R /D N  2>&1 > takeown.log
     echo granting access to %certbotfolder% for administrators
     rem icacls %certbotfolder% /t /grant Administrators:F 2>&1 > icaclsadmin.log
     rem icacls %certbotfolder% /t /grant Everyone:RX 2>&1 > icaclseveryone.log
	 rem icacls %certbotfolder% /l /t /grant Everyone:RX 2>&1 > icaclseveryoneinode.log
) else (
     echo certbot directory does not exist. No need to update permissions.
)
cscript.exe //nologo ./findApachePath.vbs %*
popd

