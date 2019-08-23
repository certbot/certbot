#!/usr/bin/env python3
import ctypes
import subprocess
import os
import sys
import shutil
import time


def main():
    print('Gather runtime data')

    try:
        subprocess.check_output(['choco', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Error: Chocolatey (https://chocolatey.org/) needs'
                           'to be installed to run this script.')

    script_path = os.path.realpath(__file__)
    repo_path = os.path.dirname(os.path.dirname(script_path))
    build_path = os.path.join(repo_path, 'windows-installer', 'build')

    venv_path = os.path.join(build_path, 'venv-config')
    venv_python = os.path.join(venv_path, 'Scripts', 'python.exe')
    installer_cfg_path = os.path.join(build_path, 'installer.cfg')
    wheels_path = os.path.join(build_path, 'wheels')

    certbot_version = subprocess.check_output([sys.executable, '-c', 'import certbot; print(certbot.__version__)'],
                                              universal_newlines=True, cwd=repo_path).strip()

    certbot_packages = ['acme', '.']
    certbot_packages.extend([name for name in os.listdir(repo_path) if name.startswith('certbot-dns-')])

    print('Copy assets')

    if os.path.exists(build_path):
        os.rename(build_path, '{0}.{1}.bak'.format(build_path, int(time.time())))
    os.makedirs(build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'certbot.ico'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'run.bat'), build_path)

    print('Prepare pynsist config')

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
installer_name=certbot-{certbot_version}-win32_installer.exe

[Python]
version=3.7.4
bitness=32

[Include]
local_wheels=wheels\*.whl
files=run.bat

[Command certbot]
entry_point=certbot.main:main
""".format(certbot_version=certbot_version))

    print('Prepare build environment')

    subprocess.check_call([sys.executable, '-m', 'venv', venv_path])
    subprocess.check_call(['choco', 'upgrade', '-y', 'nsis'])
    subprocess.check_call([venv_python, '-m', 'pip', 'install', '--upgrade', 'pip'])

    subprocess.check_call([venv_python, '-m', 'pip', 'install', 'wheel', 'pynsist'])

    print('Compile wheels')

    os.makedirs(wheels_path)
    wheels_project = [os.path.join(repo_path, package) for package in certbot_packages]
    command = [venv_python, '-m', 'pip', 'wheel', '-w', wheels_path]
    command.extend(wheels_project)
    subprocess.check_call(command)

    print('Build the installer')

    subprocess.check_call([os.path.join(venv_path, 'Scripts', 'pynsist.exe'), installer_cfg_path])

    print('Done')


if __name__ == '__main__':
    if not os.name == 'nt':
        raise RuntimeError('This script must be run under Windows.')
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        raise RuntimeError('This script must be run with administrator privileges.')
    main()
