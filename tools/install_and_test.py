#!/usr/bin/env python
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package. If CERTBOT_NO_PIN is set not
# set to 1, packages are installed using pinned versions of all of our
# dependencies. See pip_install.py for more information on the versions pinned
# to.
import os
import sys
import tempfile
import shutil
import subprocess
import re

def call_with_print(command, cwd=None):
    print(command)
    subprocess.call(command, shell=True, cwd=cwd or os.getcwd())

def main():
    if os.environ.get('CERTBOT_NO_PIN') == '1':
        command = [sys.executable, '-m', 'pip', '-q', '-e']
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        command = [sys.executable, os.path.join(script_dir, 'pip_install_editable.py')]
    
    for requirement in sys.argv[1:]:
        current_command = command[:]
        current_command.append(requirement)
        call_with_print(' '.join(current_command))
        pkg = re.sub(r'\[\w+\]', '', requirement)
        pkg = pkg.replace('_', '-')

        if pkg == '.':
            pkg = 'certbot'

        try:
            temp_cwd = tempfile.mkdtemp()
            call_with_print(' '.join([
                sys.executable, '-m', 'pytest', '--numprocesses', 'auto',
                '--quiet', '--pyargs', pkg]), cwd=temp_cwd)
        finally:
            shutil.rmtree(temp_cwd)

if __name__ == '__main__':
    main()
