@echo off
:: Try to find Python
set found_python=false
where python > nul 2> nul && set found_python=true

if %found_python% == true goto testpython3

:installpython3
:: If Python 3.X is not found, download and install it
echo Python 3 is not installed.
echo Downloading installer for Python 3.7.0 ...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe', 'python-install.exe')"
echo Installing Python 3.7.0 ...
python-install.exe /quiet InstallAllUsers=0 Include_launcher=0 Include_test=0 PrependPath=1
del python-install.exe

:: Add for this shell the Python executables to path (will be added automatically from registry in the next shell)
set PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python37-32\;%LOCALAPPDATA%\Programs\Python\Python37-32\Scripts\

:testpython3
:: Test Python version, we need version 3 to use embedded venv module
for /f "tokens=* USEBACKQ" %%x in (`python --version`) do set python_version=%%x
if /i "%python_version:~0,9%" neq "Python 3." goto installpython3

:: Install a custom venv and enable it
set script_path=%~dp0
python -m venv %current_path%\venv-win-certbot-auto
call %current_path%\venv-win-certbot-auto\Scripts\activate.bat

:: Update cerbot
pip install --upgrade -e %script_path% > nul 2> nul

:: Execute certbot with given arguments
certbot %*

:: Leave venv
call %current_path%\venv-win-certbot-auto\Scripts\deactivate.bat