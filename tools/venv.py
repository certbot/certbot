#!/usr/bin/env python3
# Developer virtualenv setup for Certbot client
"""Aids in creating a developer virtual environment for Certbot.

When this module is run as a script, it takes the arguments that should
be passed to pip to install the Certbot packages as command line
arguments. If no arguments are provided, all Certbot packages and their
development dependencies are installed. The virtual environment will be
created with the name "venv" in the current working directory. You can
change the name of the virtual environment by setting the environment
variable VENV_NAME.

"""

from __future__ import print_function

import glob
import os
import re
import shutil
import subprocess
import sys
import time

REQUIREMENTS = [
    '-e acme[test]',
    '-e certbot[all]',
    '-e certbot-apache',
 #   '-e certbot-dns-cloudflare',
 #   '-e certbot-dns-digitalocean',
 #   '-e certbot-dns-dnsimple',
 #   '-e certbot-dns-dnsmadeeasy',
 #   '-e certbot-dns-gehirn',
 #   '-e certbot-dns-google',
 #   '-e certbot-dns-linode',
 #   '-e certbot-dns-luadns',
 #   '-e certbot-dns-nsone',
 #   '-e certbot-dns-ovh',
 #   '-e certbot-dns-rfc2136',
 #   '-e certbot-dns-route53',
 #   '-e certbot-dns-sakuracloud',
    '-e certbot-nginx',
    '-e certbot-compatibility-test',
    '-e certbot-ci',
    '-e letstest',
]

if sys.platform == 'win32':
    REQUIREMENTS.append('-e windows-installer')
    REQUIREMENTS.remove('-e certbot-apache')
    REQUIREMENTS.remove('-e certbot-compatibility-test')

VERSION_PATTERN = re.compile(r'^(\d+)\.(\d+).*$')


class PythonExecutableNotFoundError(Exception):
    pass


def find_python_executable() -> str:
    """
    Find the relevant python executable that is of the given python major version.
    Will test, in decreasing priority order:

    * the current Python interpreter
    * 'pythonX' executable in PATH (with X the given major version) if available
    * 'python' executable in PATH if available
    * Windows Python launcher 'py' executable in PATH if available

    Incompatible python versions for Certbot will be evicted (e.g. Python 3
    versions less than 3.7).

    :rtype: str
    :return: the relevant python executable path
    :raise RuntimeError: if no relevant python executable path could be found
    """
    python_executable_path = None

    # First try, current python executable
    if _check_version('{0}.{1}.{2}'.format(
            sys.version_info[0], sys.version_info[1], sys.version_info[2])):
        return sys.executable

    # Second try, with python executables in path
    for one_version in ('3', '',):
        try:
            one_python = 'python{0}'.format(one_version)
            output = subprocess.check_output([one_python, '--version'],
                                             universal_newlines=True, stderr=subprocess.STDOUT)
            if _check_version(output.strip().split()[1]):
                return subprocess.check_output([one_python, '-c',
                                                'import sys; sys.stdout.write(sys.executable);'],
                                               universal_newlines=True)
        except (subprocess.CalledProcessError, OSError):
            pass

    # Last try, with Windows Python launcher
    try:
        output_version = subprocess.check_output(['py', '-3', '--version'],
                                                 universal_newlines=True, stderr=subprocess.STDOUT)
        if _check_version(output_version.strip().split()[1]):
            return subprocess.check_output(['py', env_arg, '-c',
                                            'import sys; sys.stdout.write(sys.executable);'],
                                           universal_newlines=True)
    except (subprocess.CalledProcessError, OSError):
        pass

    if not python_executable_path:
        raise RuntimeError('Error, no compatible Python executable for Certbot could be found.')


def _check_version(version_str):
    search = VERSION_PATTERN.search(version_str)

    if not search:
        return False

    version = (int(search.group(1)), int(search.group(2)))

    if version >= (3, 7):
        return True

    print('Incompatible python version for Certbot found: {0}'.format(version_str))
    return False


def subprocess_with_print(cmd, env=None, shell=False):
    if env is None:
        env = os.environ
    print('+ {0}'.format(subprocess.list2cmdline(cmd)) if isinstance(cmd, list) else cmd)
    subprocess.check_call(cmd, env=env, shell=shell)


def subprocess_output_with_print(cmd, env=None, shell=False):
    if env is None:
        env = os.environ
    print('+ {0}'.format(subprocess.list2cmdline(cmd)) if isinstance(cmd, list) else cmd)
    return subprocess.check_output(cmd, env=env, shell=shell)


def get_venv_python_path(venv_path):
    python_linux = os.path.join(venv_path, 'bin/python')
    if os.path.isfile(python_linux):
        return os.path.abspath(python_linux)
    python_windows = os.path.join(venv_path, 'Scripts\\python.exe')
    if os.path.isfile(python_windows):
        return os.path.abspath(python_windows)

    raise ValueError((
        'Error, could not find python executable in venv path {0}: is it a valid venv ?'
        .format(venv_path)))


def prepare_venv_path(venv_name):
    """Determines the venv path and prepares it for use.

    This function cleans up any Python eggs in the current working directory
    and ensures the venv path is available for use. The path used is the
    VENV_NAME environment variable if it is set and venv_name otherwise. If
    there is already a directory at the desired path, the existing directory is
    renamed by appending a timestamp to the directory name.

    :param str venv_name: The name or path at where the virtual
        environment should be created if VENV_NAME isn't set.

    :returns: path where the virtual environment should be created
    :rtype: str

    """
    for path in glob.glob('*.egg-info'):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    env_venv_name = os.environ.get('VENV_NAME')
    if env_venv_name:
        print('Creating venv at {0}'
              ' as specified in VENV_NAME'.format(env_venv_name))
        venv_name = env_venv_name

    if os.path.isdir(venv_name):
        os.rename(venv_name, '{0}.{1}.bak'.format(venv_name, int(time.time())))

    return venv_name


def install_packages(venv_name, pip_args):
    """Installs packages in the given venv.

    :param str venv_name: The name or path at where the virtual
        environment should be created.
    :param pip_args: Command line arguments that should be given to
        pip to install packages
    :type pip_args: `list` of `str`

    """
    # Using the python executable from venv, we ensure to execute following commands in this venv.
    py_venv = get_venv_python_path(venv_name)
    command = [py_venv, os.path.abspath('tools/pip_install.py')]
    command.extend(pip_args)
    subprocess_with_print(command)

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


def create_venv(venv_path):
    """Create a Python virtual environment at venv_path.

    :param str venv_path: path where the venv should be created

    """
    python = find_python_executable()
    command = [python, '-m', 'venv', venv_path]
    subprocess_with_print(command)


def main(pip_args=None):
    venv_path = prepare_venv_path('venv')
    create_venv(venv_path)

    if not pip_args:
        pip_args = REQUIREMENTS

    install_packages(venv_path, pip_args)


if __name__ == '__main__':
    main(sys.argv[1:])
