#!/usr/bin/env python

from __future__ import print_function

import os
import shutil
import glob
import time
import subprocess
import sys
import re

VERSION_PATTERN = re.compile(r'^(\d+)\.(\d+).*$')


class PythonExecutableNotFoundError(Exception):
    pass


def find_python_executable(python_major):
    # type: (int) -> str
    """
    Find the relevant python executable that is of the given python major version.
    Will test, in decreasing priority order:
    * the current Python interpreter
    * 'pythonX' executable in PATH (with X the given major version) if available
    * 'python' executable in PATH if available
    * Windows Python launcher 'py' executable in PATH if available
    Incompatible python versions for Certbot will be evicted (eg. Python < 3.5 on Windows)
    :param int python_major: the Python major version to target (2 or 3)
    :rtype: str
    :return: the relevant python executable path
    :raise RuntimeError: if no relevant python executable path could be found
    """
    python_executable_path = None

    # First try, current python executable
    if _check_version('{0}.{1}.{2}'.format(
            sys.version_info[0], sys.version_info[1], sys.version_info[2]), python_major):
        return sys.executable

    # Second try, with python executables in path
    versions_to_test = ['2.7', '2', ''] if python_major == 2 else ['3', '']
    for one_version in versions_to_test:
        try:
            one_python = 'python{0}'.format(one_version)
            output = subprocess.check_output([one_python, '--version'],
                                             universal_newlines=True, stderr=subprocess.STDOUT)
            if _check_version(output.strip().split()[1], python_major):
                return subprocess.check_output([one_python, '-c',
                                                'import sys; sys.stdout.write(sys.executable);'],
                                               universal_newlines=True)
        except (subprocess.CalledProcessError, OSError):
            pass

    # Last try, with Windows Python launcher
    try:
        env_arg = '-{0}'.format(python_major)
        output_version = subprocess.check_output(['py', env_arg, '--version'],
                                                 universal_newlines=True, stderr=subprocess.STDOUT)
        if _check_version(output_version.strip().split()[1], python_major):
            return subprocess.check_output(['py', env_arg, '-c',
                                            'import sys; sys.stdout.write(sys.executable);'],
                                           universal_newlines=True)
    except (subprocess.CalledProcessError, OSError):
        pass

    if not python_executable_path:
        raise RuntimeError('Error, no compatible Python {0} executable for Certbot could be found.'
                           .format(python_major))


def _check_version(version_str, major_version):
    search = VERSION_PATTERN.search(version_str)

    if not search:
        return False

    version = (int(search.group(1)), int(search.group(2)))

    minimal_version_supported = (2, 7)
    if major_version == 3 and os.name == 'nt':
        minimal_version_supported = (3, 5)
    elif major_version == 3:
        minimal_version_supported = (3, 4)

    if version >= minimal_version_supported:
        return True

    print('Incompatible python version for Certbot found: {0}'.format(version_str))
    return False


def subprocess_with_print(command):
    print(command)
    subprocess.check_call(command, shell=True)


def get_venv_python(venv_path):
    python_linux = os.path.join(venv_path, 'bin/python')
    if os.path.isfile(python_linux):
        return python_linux
    python_windows = os.path.join(venv_path, 'Scripts\\python.exe')
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

    subprocess_with_print('"{0}" -m virtualenv --no-site-packages --setuptools {1} {2}'
                          .format(sys.executable, venv_name, venv_args))

    python_executable = get_venv_python(venv_name)

    subprocess_with_print('"{0}" {1}'.format(
        python_executable,
        os.path.normpath('./letsencrypt-auto-source/pieces/pipstrap.py')))
    subprocess_with_print('"{0}" {1} {2}'.format(
        python_executable,
        os.path.normpath('./tools/pip_install.py'),
        ' '.join(args)))

    if os.path.isdir(os.path.join(venv_name, 'bin')):
        # Linux/OSX specific
        print('-------------------------------------------------------------------')
        print('Please run the following command to activate developer environment:')
        print('source {0}/bin/activate'.format(venv_name))
        print('-------------------------------------------------------------------')
    elif os.path.isdir(os.path.join(venv_name, 'Scripts')):
        # Windows specific
        print('---------------------------------------------------------------------------')
        print('Please run one of the following commands to activate developer environment:')
        print('{0}\\Scripts\\activate.bat (for Batch)'.format(venv_name))
        print('.\\{0}\\Scripts\\Activate.ps1 (for Powershell)'.format(venv_name))
        print('---------------------------------------------------------------------------')
    else:
        raise ValueError('Error, directory {0} is not a valid venv.'.format(venv_name))


if __name__ == '__main__':
    main(os.environ.get('VENV_NAME', 'venv'),
         os.environ.get('VENV_ARGS', ''),
         sys.argv[1:])
