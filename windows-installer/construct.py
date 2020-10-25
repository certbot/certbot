#!/usr/bin/env python3
import contextlib
import ctypes
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

PYTHON_VERSION = (3, 7, 4)
PYTHON_BITNESS = 32
PYWIN32_VERSION = 227  # do not forget to edit pywin32 dependency accordingly in setup.py
NSIS_VERSION = '3.04'


def main():
    build_path, repo_path, venv_path, venv_python = _prepare_environment()

    _copy_assets(build_path, repo_path)

    installer_cfg_path = _generate_pynsist_config(repo_path, build_path)

    _prepare_build_tools(venv_path, venv_python, repo_path)
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

    certbot_packages = ['acme', 'certbot']
    # Uncomment following line to include all DNS plugins in the installer
    # certbot_packages.extend([name for name in os.listdir(repo_path) if name.startswith('certbot-dns-')])
    wheels_project = [os.path.join(repo_path, package) for package in certbot_packages]

    with _prepare_constraints(repo_path) as constraints_file_path:
        command = [venv_python, '-m', 'pip', 'wheel', '-w', wheels_path, '--constraint', constraints_file_path]
        command.extend(wheels_project)
        subprocess.check_call(command)


def _prepare_build_tools(venv_path, venv_python, repo_path):
    print('Prepare build tools')
    subprocess.check_call([sys.executable, '-m', 'venv', venv_path])
    subprocess.check_call([venv_python, os.path.join(repo_path, 'letsencrypt-auto-source', 'pieces', 'pipstrap.py')])
    subprocess.check_call([venv_python, os.path.join(repo_path, 'tools', 'pip_install.py'), 'pynsist'])
    subprocess.check_call(['choco', 'upgrade', '--allow-downgrade', '-y', 'nsis', '--version', NSIS_VERSION])


@contextlib.contextmanager
def _prepare_constraints(repo_path):
    requirements = os.path.join(repo_path, 'letsencrypt-auto-source', 'pieces', 'dependency-requirements.txt')
    constraints = subprocess.check_output(
        [sys.executable, os.path.join(repo_path, 'tools', 'strip_hashes.py'), requirements],
        universal_newlines=True)
    workdir = tempfile.mkdtemp()
    try:
        constraints_file_path = os.path.join(workdir, 'constraints.txt')
        with open(constraints_file_path, 'a') as file_h:
            file_h.write(constraints)
            file_h.write('pywin32=={0}'.format(PYWIN32_VERSION))
        yield constraints_file_path
    finally:
        shutil.rmtree(workdir)


def _copy_assets(build_path, repo_path):
    print('Copy assets')
    if os.path.exists(build_path):
        os.rename(build_path, '{0}.{1}.bak'.format(build_path, int(time.time())))
    os.makedirs(build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'certbot.ico'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'run.bat'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'template.nsi'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'renew-up.ps1'), build_path)
    shutil.copy(os.path.join(repo_path, 'windows-installer', 'renew-down.ps1'), build_path)


def _generate_pynsist_config(repo_path, build_path):
    print('Generate pynsist configuration')

    pywin32_paths_file = os.path.join(build_path, 'pywin32_paths.py')

    # Pywin32 uses non-standard folders to hold its packages. We need to instruct pynsist bootstrap
    # explicitly to add them into sys.path. This is done with a custom "pywin32_paths.py" that is
    # referred in the pynsist configuration as an "extra_preamble".
    # Reference example: https://github.com/takluyver/pynsist/tree/master/examples/pywebview
    with open(pywin32_paths_file, 'w') as file_h:
        file_h.write('''\
pkgdir = os.path.join(os.path.dirname(installdir), 'pkgs')

sys.path.extend([
    os.path.join(pkgdir, 'win32'),
    os.path.join(pkgdir, 'win32', 'lib'),
])

# Preload pywintypes and pythoncom
pwt = os.path.join(pkgdir, 'pywin32_system32', 'pywintypes{0}{1}.dll')
pcom = os.path.join(pkgdir, 'pywin32_system32', 'pythoncom{0}{1}.dll')
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import imp
imp.load_dynamic('pywintypes', pwt)
imp.load_dynamic('pythoncom', pcom)
'''.format(PYTHON_VERSION[0], PYTHON_VERSION[1]))

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
extra_preamble=pywin32_paths.py
'''.format(certbot_version=certbot_version,
           installer_suffix='win_amd64' if PYTHON_BITNESS == 64 else 'win32',
           python_bitness=PYTHON_BITNESS,
           python_version='.'.join(str(item) for item in PYTHON_VERSION)))

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
    main()
