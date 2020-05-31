#!C:\Users\suhail.sullad\certbot\buildop\windows\apache\acmeApacheWindowsController\Certbot\Python\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'distro==1.4.0','console_scripts','distro'
__requires__ = 'distro==1.4.0'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('distro==1.4.0', 'console_scripts', 'distro')()
    )
