#!/usr/bin/env python
# Developer virtualenv setup for Certbot client
import os
import sys

import _venv_common


def create_venv(venv_path):
    """Create a Python 2 virtual environment at venv_path.

    :param str venv_path: path where the venv should be created

    """
    python2 = _venv_common.find_python_executable(2)
    command = [sys.executable, '-m', 'virtualenv', '--python', python2, venv_path]

    environ = os.environ.copy()
    environ['VIRTUALENV_NO_DOWNLOAD'] = '1'
    _venv_common.subprocess_with_print(command, environ)


def main(pip_args=None):
    if os.name == 'nt':
        raise ValueError('Certbot for Windows is not supported on Python 2.x.')

    venv_path = _venv_common.prepare_venv_path('venv')
    create_venv(venv_path)

    if not pip_args:
        pip_args = _venv_common.REQUIREMENTS

    _venv_common.install_packages(venv_path, pip_args)


if __name__ == '__main__':
    main(sys.argv[1:])
