import os
import subprocess
import tempfile
import shutil
import re

import pytest


@pytest.fixture(scope='session')
def acme_url():
    integration = os.environ.get('CERTBOT_INTEGRATION')

    if integration == 'boulder-v1':
        return 'http://localhost:4000/directory'
    if integration == 'boulder-v2':
        return 'http://localhost:4001/directory'
    if integration == 'pebble' or integration == 'pebble-strict':
        return 'https://localhost:14000/dir'

    raise ValueError('Invalid CERTBOT_INTEGRATION value')


@pytest.fixture(scope='session')
def workspace():
    workspace = tempfile.mkdtemp()
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace)


@pytest.fixture(scope='session')
def tls_sni_01_port():
    return 5001


@pytest.fixture(scope='session')
def http_01_port():
    return 5002


@pytest.fixture(scope='session')
def certbot_test_no_force_renew(workspace, acme_url):
    certbot = _find_certbot_executable()
    sources = _find_certbot_sources()
    omit_patterns = (
        '*/*.egg-info/*,*/dns_common*,*/setup.py,*/test_*,*/tests/*,'
        '$omit_patterns,*_test.py,*_test_*,certbot-apache/*,'
        '$omit_patterns,certbot-compatibility-test/*,certbot-dns*/,'
        '$omit_patterns,certbot-nginx/certbot_nginx/parser_obj.py'
    )

    def func(args):
        command = [
            'coverage', 'run', '--append', '--source', ','.join(sources), '--omit', omit_patterns,
            certbot, '--server', acme_url, '--no-verify-ssl', '--tls-sni-01-port', '5001',
            '--http-01-port', '5002', '--manual-public-ip-logging-ok', '--config-dir',
            os.path.join(workspace, 'conf'), '--work-dir', os.path.join(workspace, 'work'),
            '--non-interactive', '--no-redirect', '--agree-tos',
            '--register-unsafely-without-email', '--debug', '-vv'
        ]

        command.extend(args)

        print('Invoke command:\n{0}'.format(subprocess.list2cmdline(command)))
        subprocess.check_call(command)

    return func


@pytest.fixture(scope='session')
def certbot_test(certbot_test_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        certbot_test_no_force_renew(command)

    return func


def _find_certbot_executable():
    try:
        return subprocess.check_output('which certbot',
                                       shell=True, universal_newlines=True).strip()
    except subprocess.CalledProcessError:
        try:
            return subprocess.check_output('where certbot',
                                           shell=True, universal_newlines=True).strip()
        except subprocess.CalledProcessError:
            pass

    raise ValueError('Error, could not find certbot executable')


def _find_certbot_sources():
    script_path = os.path.realpath(__file__)
    current_dir = os.path.dirname(script_path)

    while '.git' not in os.listdir(current_dir) and current_dir != os.path.dirname(current_dir):
        current_dir = os.path.dirname(current_dir)

    dirs = os.listdir(current_dir)
    if '.git' not in dirs:
        raise ValueError('Error, could not find certbot sources root directory')

    return [os.path.join(current_dir, dir) for dir in dirs
            if (dir == 'acme' or (re.match('^certbot.*$', dir)
                                  and dir not in ['certbot-ci', 'certbot.egg-info']))
            and os.path.isdir(dir)]
