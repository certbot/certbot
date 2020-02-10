import os
import time
import unittest
import subprocess
import re
from http.server import BaseHTTPRequestHandler
import threading
import socketserver
import json
import tempfile
import shutil
import warnings

import pytest
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pkg_resources


@pytest.fixture
def installer(request):
    with tempfile.TemporaryDirectory() as temp_dir:
        shutil.copy(request.config.option.installer_path, temp_dir)
        yield os.path.join(temp_dir, os.path.basename(request.config.option.installer_path))


@pytest.fixture
def github_mock(installer):
    server = None
    try:
        class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            pass

        class GitHubMock(BaseHTTPRequestHandler):
            def do_GET(self):
                if re.match(r'^.*/release/latest$', self.path):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(
                        {
                            'assets': [{
                                'name': os.path.basename(installer),
                                'browser_download_url': 'https://localhost/{0}'.format(os.path.basename(installer))
                            }]
                        }
                    ).encode())
                elif re.match(r'^.*certbot-.*installer-win32\.exe$', self.path):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/octet-stream')
                    self.end_headers()
                    with open(installer, 'rb') as file_h:
                        self.wfile.write(file_h.read())
                else:
                    self.send_response(404)
                    self.end_headers()

        server_address = ('', 8009)
        server = ThreadedTCPServer(server_address, GitHubMock)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        yield True
    finally:
        if server:
            server.shutdown()
            server.server_close()


@pytest.fixture
def signing_cert():
    cert_thumbprint = None
    try:
        pfx_file = pkg_resources.resource_filename('windows_installer_integration_tests', 'assets/test-signing.pfx')
        output = _ps('(Import-PfxCertificate -FilePath {0} -CertStoreLocation Cert:\\LocalMachine\\Root).Thumbprint'
                     .format(pfx_file), capture_stdout=True)
        cert_thumbprint = output.strip()
        if not cert_thumbprint:
            raise RuntimeError('Error, test signing certificate could not be installed.')
        yield pfx_file
    finally:
        if cert_thumbprint:
            _ps('Get-ChildItem Cert:\\LocalMachine\\Root\\{0} | Remove-Item'.format(cert_thumbprint))


@unittest.skipIf(os.name != 'nt', reason='Windows installer tests must be run on Windows.')
def test_it(github_mock, installer, signing_cert):
    assert github_mock
    assert signing_cert

    try:
        subprocess.check_call(['certbot', '--version'])
    except (subprocess.CalledProcessError, OSError):
        pass
    else:
        raise AssertionError('Expect certbot to not be available in the PATH.')

    try:
        # Install certbot
        subprocess.check_call([installer, '/S'])

        # Assert certbot is installed and runnable
        output = subprocess.check_output(['certbot', '--version'], universal_newlines=True)
        assert re.match(r'^certbot \d+\.\d+\.\d+.*$', output), 'Flag --version does not output a version.'

        # Assert renew task is installed and ready
        output = _ps('(Get-ScheduledTask -TaskName "Certbot Renew Task").State', capture_stdout=True)
        assert output.strip() == 'Ready'

        # Assert renew task is working
        now = time.time()
        _ps('Start-ScheduledTask -TaskName "Certbot Renew Task"')

        status = 'Running'
        while status != 'Ready':
            status = _ps('(Get-ScheduledTask -TaskName "Certbot Renew Task").State', capture_stdout=True).strip()
            time.sleep(1)

        log_path = os.path.join('C:\\', 'Certbot', 'log', 'letsencrypt.log')

        modification_time = os.path.getmtime(log_path)
        assert now < modification_time, 'Certbot log file has not been modified by the renew task.'

        with open(log_path) as file_h:
            data = file_h.read()
        assert 'no renewal failures' in data, 'Renew task did not execute properly.'

    finally:
        # Sadly this command cannot work in non interactive mode: uninstaller will ask explicitly permission in an UAC prompt
        # print('Uninstalling Certbot ...')
        # uninstall_path = _ps('(gci "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"'
        #                      ' | foreach { gp $_.PSPath }'
        #                      ' | ? { $_ -match "Certbot" }'
        #                      ' | select UninstallString)'
        #                      '.UninstallString', capture_stdout=True)
        # subprocess.check_call([uninstall_path, '/S'])
        pass


def _ps(powershell_str, capture_stdout=False):
    fn = subprocess.check_output if capture_stdout else subprocess.check_call
    return fn(['powershell.exe', '-c', powershell_str], universal_newlines=True)
