#!/usr/bin/env python

from __future__ import print_function

import os
import shutil
import glob
import time
import subprocess
import sys

def subprocess_with_print(command):
    print(command)
    subprocess.call(command, shell=True)

def get_venv_python(venv_path):
    python_linux = os.path.join(venv_path, 'bin/python')
    python_windows = os.path.join(venv_path, 'Scripts\\python.exe')
    if os.path.isfile(python_linux):
        return python_linux
    if os.path.isfile(python_windows):
        return python_windows

    raise ValueError((
        'Error, could not find python executable in venv path {0}: is it a valid venv ?'
        .format(venv_path)))

def main(venv_name, venv_args, args):
    for path in glob.glob('*.egg-info'):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    if os.path.isdir(venv_name):
        os.rename(venv_name, '{0}.{1}.bak'.format(venv_name, int(time.time())))

    subprocess_with_print(' '.join([
        sys.executable, '-m', 'virtualenv', '--no-site-packages', '--setuptools',
        venv_name, venv_args]))

    python_executable = get_venv_python(venv_name)

    subprocess_with_print(' '.join([
        python_executable, os.path.normpath('./letsencrypt-auto-source/pieces/pipstrap.py')]))
    command = [python_executable, os.path.normpath('./tools/pip_install.py')]
    command.extend(args)
    subprocess_with_print(' '.join(command))

    print('-------------------------------------------------------------------')
    print('Please run the following command to activate developer environment:')
    print('source {0}/bin/activate'.format(venv_name))
    print('-------------------------------------------------------------------')

if __name__ == '__main__':
    main(os.environ.get('VENV_NAME', 'venv'), os.environ.get('VENV_ARGS', ''), sys.argv[1:])
