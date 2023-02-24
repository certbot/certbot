"""Module executing integration tests for the windows installer."""
import os
import re
import subprocess
import time
from typing import Any

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='Windows installer tests must be run on Windows.')
def test_it(request: pytest.FixtureRequest) -> None:
    try:
        subprocess.check_call(['certbot', '--version'])
    except (subprocess.CalledProcessError, OSError):
        pass
    else:
        raise AssertionError('Expect certbot to not be available in the PATH.')

    try:
        # Install certbot
        subprocess.check_call([request.config.option.installer_path, '/S'])

        # Assert certbot is installed and runnable
        output = subprocess.check_output(['certbot', '--version'], universal_newlines=True)
        assert re.match(r'^certbot \d+\.\d+\.\d+.*$',
                        output), 'Flag --version does not output a version.'

        # Assert renew task is installed and ready
        output = _ps('(Get-ScheduledTask -TaskName "Certbot Renew Task").State',
                     capture_stdout=True)
        assert output.strip() == 'Ready'

        # Assert renew task is working
        now = time.time()
        _ps('Start-ScheduledTask -TaskName "Certbot Renew Task"')

        status = 'Running'
        while status != 'Ready':
            status = _ps('(Get-ScheduledTask -TaskName "Certbot Renew Task").State',
                         capture_stdout=True).strip()
            time.sleep(1)

        log_path = os.path.join('C:\\', 'Certbot', 'log', 'letsencrypt.log')

        modification_time = os.path.getmtime(log_path)
        assert now < modification_time, 'Certbot log file has not been modified by the renew task.'

        with open(log_path) as file_h:
            data = file_h.read()
        assert 'no renewal failures' in data, 'Renew task did not execute properly.'

    finally:
        # Sadly this command cannot work in non interactive mode: uninstaller will
        # ask explicitly permission in an UAC prompt
        # print('Uninstalling Certbot ...')
        # uninstall_path = _ps('(gci "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"'  # pylint: disable=line-too-long
        #                      ' | foreach { gp $_.PSPath }'
        #                      ' | ? { $_ -match "Certbot" }'
        #                      ' | select UninstallString)'
        #                      '.UninstallString', capture_stdout=True)
        # subprocess.check_call([uninstall_path, '/S'])
        pass


def _ps(powershell_str: str, capture_stdout: bool = False) -> Any:
    fn = subprocess.check_output if capture_stdout else subprocess.check_call
    return fn(['powershell.exe', '-c', powershell_str],  # type: ignore[operator]
              universal_newlines=True)
