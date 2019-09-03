#!/usr/bin/env python3
import ctypes
import struct
import subprocess
import os
import sys
import shutil
import time


PYTHON_VERSION = (3, 7, 4)
PYTHON_BITNESS = 32


def main():
    build_path, repo_path, venv_path, venv_python = _prepare_environment()

    _copy_assets(build_path, repo_path)

    installer_cfg_path = _generate_pynsist_config(repo_path, build_path)

    _prepare_build_tools(venv_path, venv_python)
    _compile_wheels(repo_path, build_path, venv_python)
    _build_installer(installer_cfg_path, venv_path)

    print('Done')


def _build_installer(installer_cfg_path, venv_path):
    print('Build the installer')
    subprocess.check_call([os.path.join(venv_path, 'Scripts', 'pynsist.exe'), installer_cfg_path])


def _compile_wheels(repo_path, build_path, venv_python):
    print('Compile wheels')

    wheels_path = os.path.join(build_path, 'wheels')
    os.makedirs(wheels_path)

    certbot_packages = ['acme', '.']
    # Uncomment following line to include all DNS plugins in the installer
    # certbot_packages.extend([name for name in os.listdir(repo_path) if name.startswith('certbot-dns-')])
    wheels_project = [os.path.join(repo_path, package) for package in certbot_packages]

    command = [venv_python, '-m', 'pip', 'wheel', '-w', wheels_path]
    command.extend(wheels_project)
    subprocess.check_call(command)


def _prepare_build_tools(venv_path, venv_python):
    print('Prepare build tools')
    subprocess.check_call([sys.executable, '-m', 'venv', venv_path])
    subprocess.check_call(['choco', 'upgrade', '-y', 'nsis'])
    subprocess.check_call([venv_python, '-m', 'pip', 'install', '--upgrade', 'pip'])
    subprocess.check_call([venv_python, '-m', 'pip', 'install', 'wheel', 'pynsist'])


def _copy_assets(build_path, repo_path):
    print('Copy assets')
    if os.path.exists(build_path):
        os.rename(build_path, '{0}.{1}.bak'.format(build_path, int(time.time())))
    os.makedirs(build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'certbot.ico'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'run.bat'), build_path)


def _generate_pynsist_config(repo_path, build_path):
    print('Generate pynsist configuration')

    installer_cfg_path = os.path.join(build_path, 'installer.cfg')

    certbot_version = subprocess.check_output([sys.executable, '-c', 'import certbot; print(certbot.__version__)'],
                                              universal_newlines=True, cwd=repo_path).strip()

    with open(os.path.join(installer_cfg_path), 'w') as file_h:
        file_h.write("""\
[Application]
name=Certbot
version={certbot_version}
icon=certbot.ico
publisher=Electronic Frontier Foundation
target=$INSTDIR\\run.bat

[Build]
directory=nsis
installer_name=certbot-{certbot_version}-installer-{installer_suffix}.exe

[Python]
version={python_version}
bitness={python_bitness}

[Include]
local_wheels=wheels\\*.whl
files=run.bat

[Command certbot]
entry_point=certbot.main:main
""".format(certbot_version=certbot_version,
           installer_suffix='win_amd64' if PYTHON_BITNESS == 64 else 'win32',
           python_bitness=PYTHON_BITNESS,
           python_version='.'.join([str(item) for item in PYTHON_VERSION])))

        return installer_cfg_path


def _prepare_environment():
    print('Prepare environment')
    try:
        subprocess.check_output(['choco', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Error: Chocolatey (https://chocolatey.org/) needs '
                           'to be installed to run this script.')
    script_path = os.path.realpath(__file__)
    repo_path = os.path.dirname(os.path.dirname(script_path))
    build_path = os.path.join(repo_path, 'windows-installer', 'build')
    venv_path = os.path.join(build_path, 'venv-config')
    venv_python = os.path.join(venv_path, 'Scripts', 'python.exe')

    return build_path, repo_path, venv_path, venv_python


if __name__ == '__main__':
    if not os.name == 'nt':
        raise RuntimeError('This script must be run under Windows.')

    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        # Administrator privileges are required to properly install NSIS through Chocolatey
        raise RuntimeError('This script must be run with administrator privileges.')

    if sys.version_info[:2] != PYTHON_VERSION[:2]:
        raise RuntimeError('This script must be run with Python {0}'
                           .format('.'.join([str(item) for item in PYTHON_VERSION[0:2]])))

    if struct.calcsize('P') * 8 != PYTHON_BITNESS:
        raise RuntimeError('This script must be run with a {0} bit version of Python.'
                           .format(PYTHON_BITNESS))
    main()
