#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, tools/oldest_constraints.txt is used, otherwise, tools/requirements.txt
# is used.

from __future__ import absolute_import
from __future__ import print_function

import os
import subprocess
import sys
import tempfile


def find_tools_path():
    return os.path.dirname(os.path.realpath(__file__))


def call_with_print(command, env=None):
    if not env:
        env = os.environ
    print(command)
    subprocess.check_call(command, shell=True, env=env)


def pip_install_with_print(args_str, env=None):
    if not env:
        env = os.environ
    command = ['"', sys.executable, '" -m pip install --disable-pip-version-check ', args_str]
    call_with_print(''.join(command), env=env)


def main(args):
    tools_path = find_tools_path()

    with tempfile.TemporaryDirectory() as working_dir:
        repo_path = os.path.dirname(tools_path)
        if os.environ.get('CERTBOT_OLDEST') == '1':
            constraints_path = os.path.normpath(os.path.join(
                repo_path, 'tools', 'oldest_constraints.txt'))
        else:
            constraints_path = os.path.normpath(os.path.join(
                repo_path, 'tools', 'requirements.txt'))

        env = os.environ.copy()
        env["PIP_CONSTRAINT"] = constraints_path

        pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
