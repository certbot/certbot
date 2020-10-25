#!/usr/bin/env python
"""Aids in creating a developer virtual environment for Certbot.

When this module is run as a script, it takes the arguments that should
be passed to pip to install the Certbot packages as command line
arguments. The virtual environment will be created with the name "venv"
in the current working directory and will use the default version of
Python for the virtualenv executable in your PATH. You can change the
name of the virtual environment by setting the environment variable
VENV_NAME.
"""

from __future__ import print_function

from distutils.version import LooseVersion
import glob
import os
import re
import shutil
import subprocess
import sys
import time

REQUIREMENTS = [
    '-e acme[dev]',
    '-e certbot[dev,docs]',
    '-e certbot-apache',
    '-e certbot-dns-cloudflare',
    '-e certbot-dns-cloudxns',
    '-e certbot-dns-digitalocean',
    '-e certbot-dns-dnsimple',
    '-e certbot-dns-dnsmadeeasy',
    '-e certbot-dns-gehirn',
    '-e certbot-dns-google',
    '-e certbot-dns-linode',
    '-e certbot-dns-luadns',
    '-e certbot-dns-nsone',
    '-e certbot-dns-ovh',
    '-e certbot-dns-rfc2136',
    '-e certbot-dns-route53',
    '-e certbot-dns-sakuracloud',
    '-e certbot-nginx',
    '-e certbot-compatibility-test',
    '-e certbot-ci',
]

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

    Incompatible python versions for Certbot will be evicted (e.g. Python 3
    versions less than 3.6).

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
    if major_version == 3:
        minimal_version_supported = (3, 6)

    if version >= minimal_version_supported:
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
    subprocess_with_print([py_venv, os.path.abspath('letsencrypt-auto-source/pieces/pipstrap.py')])
    # We only use this value during pip install because:
    # 1) We're really only adding it for installing cryptography, which happens here, and
    # 2) There are issues with calling it along with VIRTUALENV_NO_DOWNLOAD, which applies at the
    #    steps above, not during pip install.
    env_pip_no_binary = os.environ.get('CERTBOT_PIP_NO_BINARY')
    if env_pip_no_binary:
        # Check OpenSSL version. If it's too low, don't apply the env variable.
        openssl_version_string = str(subprocess_output_with_print(['openssl', 'version']))
        matches = re.findall(r'OpenSSL ([^ ]+) ', openssl_version_string)
        if not matches:
            print('Could not find OpenSSL version, not setting PIP_NO_BINARY.')
        else:
            openssl_version = matches[0]

            if LooseVersion(openssl_version) >= LooseVersion('1.0.2'):
                print('Setting PIP_NO_BINARY to {0}'
                      ' as specified in CERTBOT_PIP_NO_BINARY'.format(env_pip_no_binary))
                os.environ['PIP_NO_BINARY'] = env_pip_no_binary
            else:
                print('Not setting PIP_NO_BINARY, as OpenSSL version is too old.')
    command = [py_venv, os.path.abspath('tools/pip_install.py')]
    command.extend(pip_args)
    subprocess_with_print(command)
    if 'PIP_NO_BINARY' in os.environ:
        del os.environ['PIP_NO_BINARY']

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
