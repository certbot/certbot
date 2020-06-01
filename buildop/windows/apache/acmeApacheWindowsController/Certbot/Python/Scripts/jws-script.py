#!C:\Users\suhail.sullad\certbot\buildop\windows\apache\acmeApacheWindowsController\Certbot\Python\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'josepy==1.2.0','console_scripts','jws'
__requires__ = 'josepy==1.2.0'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('josepy==1.2.0', 'console_scripts', 'jws')()
    )
