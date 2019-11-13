#!/usr/bin/env python3
# Developer virtualenv setup for Certbot client
import sys

import _venv_common


def create_venv(venv_path):
    """Create a Python 3 virtual environment at venv_path.

    :param str venv_path: path where the venv should be created

    """
    python3 = _venv_common.find_python_executable(3)
    command = [python3, '-m', 'venv', venv_path]
    _venv_common.subprocess_with_print(command)


def main(pip_args=None):
    venv_path = _venv_common.prepare_venv_path('venv3')
    create_venv(venv_path)

    if not pip_args:
        pip_args = _venv_common.REQUIREMENTS + ['-e certbot[dev3]']

    _venv_common.install_packages(venv_path, pip_args)


if __name__ == '__main__':
    main(sys.argv[1:])
