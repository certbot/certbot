#!/usr/bin/env python
import os
import shutil
import subprocess
import sys


def create_venv(venv_path, pyver, verbose):
    if os.path.exists(venv_path):
        shutil.rmtree(venv_path)

    stdout = sys.stdout if verbose == '1' else open(os.devnull, 'w')

    if int(pyver) <= 27:
        # Use virtualenv binary
        environ = os.environ.copy()
        environ['VIRTUALENV_NO_DOWNLOAD'] = '1'
        command = ['virtualenv', '--no-site-packages', '--python', sys.executable, venv_path]
        subprocess.check_call(command, stdout=stdout, env=environ)
    else:
        # Use embedded venv module in Python 3
        command = [sys.executable, '-m', 'venv', venv_path]
        subprocess.check_call(command, stdout=stdout)


if __name__ == '__main__':
    create_venv(*sys.argv[1:])
