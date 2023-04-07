#!/usr/bin/env python
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package. Packages are installed using
# pinned versions of all of our dependencies. See pip_install.py for more
# information on the versions pinned to.
import os
import re
import subprocess
import sys


def call_with_print(command):
    print(command)
    subprocess.check_call(command, shell=True)


def main(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    command = [sys.executable, os.path.join(script_dir, 'pip_install_editable.py')]

    for requirement in args:
        current_command = command[:]
        current_command.append(requirement)
        call_with_print(' '.join(current_command))
        pkg = re.sub(r'\[\w+\]', '', requirement)

        call_with_print(' '.join([
            sys.executable, '-m', 'pytest', pkg]))

if __name__ == '__main__':
    main(sys.argv[1:])
