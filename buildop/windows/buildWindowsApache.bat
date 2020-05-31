@echo on
pushd %~dp0apache\acmeApacheWindowsController\Certbot\Python
set _python=%CD%\python.exe
%_python% .\Scripts\pip.exe uninstall certbot-apache-win -y
popd
pushd %~dp0\..\..\certbot-apache-win
%_python% setup.py clean
%_python% setup.py build
%_python% setup.py install
popd