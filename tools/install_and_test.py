#!/usr/bin/env python
# pip installs the requested packages in editable mode and runs unit tests on
# them. Each package is installed and tested in the order they are provided
# before the script moves on to the next package. If CERTBOT_NO_PIN is set not
# set to 1, packages are installed using pinned versions of all of our
# dependencies. See pip_install.py for more information on the versions pinned
# to.
from __future__ import print_function

import os
import re
import subprocess
import sys

SKIP_PROJECTS_ON_WINDOWS = ['certbot-apache']


def call_with_print(command):
    print(command)
    subprocess.check_call(command, shell=True)


def main(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    command = [sys.executable, os.path.join(script_dir, 'pip_install_editable.py')]

    new_args = []
    for arg in args:
        if os.name == 'nt' and arg in SKIP_PROJECTS_ON_WINDOWS:
            print((
                'Info: currently {0} is not supported on Windows and will not be tested.'
                .format(arg)))
        else:
            new_args.append(arg)

    for requirement in new_args:
        current_command = command[:]
        current_command.append(requirement)
        call_with_print(' '.join(current_command))
        pkg = re.sub(r'\[\w+\]', '', requirement)

        call_with_print(' '.join([
            sys.executable, '-m', 'pytest', pkg]))

if __name__ == '__main__':
    main(sys.argv[1:])
