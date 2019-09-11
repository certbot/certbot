from __future__ import print_function
import ctypes
import os
import subprocess
import sys

PYTHON_BITNESS = 32


def main():
    script_dir_path = os.path.dirname(os.path.realpath(__file__))
    repo_path = os.path.dirname(script_dir_path)
    certbot_version = subprocess.check_output([sys.executable, '-c', 'import certbot; print(certbot.__version__)'],
                                              universal_newlines=True, cwd=repo_path).strip()
    installer_path = os.path.join(script_dir_path, 'build', 'nsis', 'certbot-{0}-installer-{1}.exe'
                                  .format(certbot_version, 'win_amd64' if PYTHON_BITNESS == 64 else 'win32'))

    return_code = subprocess.check_call([installer_path, '/S'])

    if return_code:
        raise RuntimeError('An error occured during certbot installation.')
    else:
        print('Certbot has been installed with success.')


if __name__ == '__main__':
    if not os.name == 'nt':
        raise RuntimeError('This script must be run under Windows.')

    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        raise RuntimeError('This script must be run with administrator privileges.')

    main()
