#!/usr/bin/env python3
import ctypes
import os
import shutil
import struct
import subprocess
import sys
import time

PYTHON_VERSION = (3, 9, 7)
PYTHON_BITNESS = 32
NSIS_VERSION = '3.06.1'


def main():
    """
    Builds the NSIS installer for the Python `pynsist` package.

    The script must be run with administrator privileges under Windows, and must be invoked
    from a 64-bit version of Python.
    """
    if os.name != 'nt':
        raise RuntimeError('This script must be run under Windows.')

    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        # Administrator privileges are required to properly install NSIS through Chocolatey
        raise RuntimeError('This script must be run with administrator privileges.')

    if sys.version_info[:2] != PYTHON_VERSION[:2]:
        raise RuntimeError('This script must be run with Python {0}'
                           .format('.'.join(str(item) for item in PYTHON_VERSION[0:2])))

    if struct.calcsize('P') * 8 != PYTHON_BITNESS:
        raise RuntimeError('This script must be run with a {0} bit version of Python.'
                           .format(PYTHON_BITNESS))

    build_path, repo_path, venv_path, venv_python = _prepare_environment()

    _copy_assets(build_path, repo_path)

    installer_cfg_path = _generate_pynsist_config(repo_path, build_path)

    _prepare_build_tools(venv_path, venv_python, repo_path)
    _compile_wheels(repo_path, build_path, venv_python)
    _build_installer(installer_cfg_path)

    print('Done')


def _build_installer(installer_cfg_path):
    print('Build the installer')
    subprocess.check_call([sys.executable, '-m', 'nsist', installer_cfg_path])


def _compile_wheels(repo_path, build_path, venv_python):
    """
    Compile wheels

        :param repo_path: Path to the repository containing the Certbot packages
        :type repo_path: str
        :param build_path: Path to a
    directory in which wheels will be compiled
        :type build_path: str
        :param venv_python: Absolute path of the Python executable within a virtual
    environment whose packages will be used for compilation. This should be passed explicitly from ``create-venv`` so that we can reliably determine
    whether Docker is being used or not. If this is `None`, it's assumed that Docker isn't being used and system Python will be targeted instead. (This
    option might change in the future.)  # noqarD, line too long (131 > 120 characters)  # noqarD, line too long (131 > 120 characters)# noqarD, line too
    long (131 > 120 characters)# noqarD, line too long (131 > 120 characters)# noqarD, line too long (131 > 120 chara...s[:-1] + '\n' + s[-1]

            ..
    note :: When using Docker for Windows or MacOS Homebrew's Python 3 version must use
    """
    print('Compile wheels')

    wheels_path = os.path.join(build_path, 'wheels')
    os.makedirs(wheels_path)

    certbot_packages = ['acme', 'certbot']
    # Uncomment following line to include all DNS plugins in the installer
    # certbot_packages.extend([name for name in os.listdir(repo_path) if name.startswith('certbot-dns-')])
    wheels_project = [os.path.join(repo_path, package) for package in certbot_packages]

    constraints_file_path = os.path.join(repo_path, 'tools', 'requirements.txt')
    env = os.environ.copy()
    env['PIP_CONSTRAINT'] = constraints_file_path
    command = [venv_python, '-m', 'pip', 'wheel', '-w', wheels_path]
    command.extend(wheels_project)
    subprocess.check_call(command, env=env)


def _prepare_build_tools(venv_path, venv_python, repo_path):
    """
    Prepare build tools

    :param str venv_path: Path to the virtual environment that will be used for building.
    :param str venv_python: Path to the Python
    executable in the virtual environment.
    :param str repo_path: Path to this repository on disk. This is needed so that pipstrap can be called with
    ``sys.executable`` set to this repository's Python executable, rather than whichever Python interpreter happens to be running this function
    (presumably a system-wide or other non-repo Python).
    """
    print('Prepare build tools')
    subprocess.check_call([sys.executable, '-m', 'venv', venv_path])
    subprocess.check_call([venv_python, os.path.join(repo_path, 'tools', 'pipstrap.py')])
    subprocess.check_call(['choco', 'upgrade', '--allow-downgrade', '-y', 'nsis', '--version', NSIS_VERSION])


def _copy_assets(build_path, repo_path):
    """
    Copy assets to build directory.

    :param str build_path: Path to the build directory.
    :param str repo_path: Path to the repository root.
    """
    print('Copy assets')
    if os.path.exists(build_path):
        os.rename(build_path, '{0}.{1}.bak'.format(build_path, int(time.time())))
    os.makedirs(build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'certbot.ico'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'run.bat'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'template.nsi'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'renew-up.ps1'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'renew-down.ps1'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'assets', 'preamble.py'), build_path)


def _generate_pynsist_config(repo_path, build_path):
    """
    Generate pynsist configuration

    :param repo_path: Path to the certbot repo containing certbot/certbot
    :type repo_path: `str` or `pathlib.Path`
    :param build_path: Path to the build directory where we'll dump files for pynsist to compile into an installer. This is also where our wheels are
    located.
        :type build_path: `str` or `pathlib.Path`

        :returns installer_cfg_file -- The path of the generated ``installer.cfg`` file that
    pynsist will use for building an installer with this configuration and ``wheels`` from this function's return value as local wheels in the installer's
    Python environment.
    """
    print('Generate pynsist configuration')

    installer_cfg_path = os.path.join(build_path, 'installer.cfg')

    certbot_pkg_path = os.path.join(repo_path, 'certbot')
    certbot_version = subprocess.check_output([sys.executable, '-c', 'import certbot; print(certbot.__version__)'],
                                              universal_newlines=True, cwd=certbot_pkg_path).strip()

    # If we change the installer name from `certbot-beta-installer-win32.exe`, it should
    # also be changed in tools/create_github_release.py
    with open(installer_cfg_path, 'w') as file_h:
        file_h.write('''\
[Application]
name=Certbot
version={certbot_version}
icon=certbot.ico
publisher=Electronic Frontier Foundation
target=$INSTDIR\\run.bat

[Build]
directory=nsis
nsi_template=template.nsi
installer_name=certbot-beta-installer-{installer_suffix}.exe

[Python]
version={python_version}
bitness={python_bitness}

[Include]
local_wheels=wheels\\*.whl
files=run.bat
      renew-up.ps1
      renew-down.ps1

[Command certbot]
entry_point=certbot.main:main
extra_preamble=preamble.py
'''.format(certbot_version=certbot_version,
           installer_suffix='win_amd64' if PYTHON_BITNESS == 64 else 'win32',
           python_bitness=PYTHON_BITNESS,
           python_version='.'.join(str(item) for item in PYTHON_VERSION)))

        return installer_cfg_path


def _prepare_environment():
    """
    Prepare environment

    :raises RuntimeError: Error: Chocolatey (http://chocolatey.org/) needs to be installed to run this script.
    """
    print('Prepare environment')
    try:
        subprocess.check_output(['choco', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Error: Chocolatey (https://chocolatey.org/) needs '
                           'to be installed to run this script.')
    script_path = os.path.realpath(__file__)
    repo_path = os.path.dirname(os.path.dirname(os.path.dirname(script_path)))
    build_path = os.path.join(repo_path, 'windows-installer', 'build')
    venv_path = os.path.join(build_path, 'venv-config')
    venv_python = os.path.join(venv_path, 'Scripts', 'python.exe')

    return build_path, repo_path, venv_path, venv_python


if __name__ == '__main__':
    main()
