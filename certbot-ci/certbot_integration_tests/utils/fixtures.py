import os
import tempfile
import subprocess
import shutil

import pytest

from certbot_integration_tests.utils import misc


@pytest.fixture(scope='session')
def acme_url():
    integration = os.environ.get('CERTBOT_INTEGRATION')

    if integration == 'boulder-v1':
        return 'http://localhost:4000/directory'
    if integration == 'boulder-v2':
        return 'http://localhost:4001/directory'
    if integration == 'pebble-nonstrict' or integration == 'pebble-strict':
        return 'https://localhost:14000/dir'

    raise ValueError('Invalid CERTBOT_INTEGRATION value: {0}'.format(integration))


@pytest.fixture(scope='session')
def tls_sni_01_port():
    return 5001


@pytest.fixture(scope='session')
def http_01_port():
    return 5002


@pytest.fixture
def workspace():
    workspace = tempfile.mkdtemp()
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace)


@pytest.fixture
def config_dir(workspace):
    return os.path.join(workspace, 'conf')


@pytest.fixture
def certbot_test_no_force_renew(workspace, config_dir, acme_url, http_01_port, tls_sni_01_port, capsys):
    def func(args):
        command = [
            'certbot', '--server', acme_url, '--no-verify-ssl', '--tls-sni-01-port',
            str(tls_sni_01_port), '--http-01-port', str(http_01_port),
            '--manual-public-ip-logging-ok', '--config-dir', config_dir, '--work-dir',
            os.path.join(workspace, 'work'), '--logs-dir', os.path.join(workspace, 'logs'),
            '--non-interactive', '--no-redirect', '--agree-tos',
            '--register-unsafely-without-email', '--debug', '-vv'
        ]

        command.extend(args)

        print('Invoke command:\n{0}'.format(subprocess.list2cmdline(command)))
        return subprocess.check_output(command, universal_newlines=True)

    return func


@pytest.fixture
def certbot_test(config_dir, acme_url, http_01_port, tls_sni_01_port):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return certbot_test_no_force_renew(command)

    return func


@pytest.fixture
def common_no_force_renew(certbot_test_no_force_renew):
    def func(args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_test_no_force_renew(command)

    return func


@pytest.fixture
def common(common_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return common_no_force_renew(command)

    return func


@pytest.fixture
def http_01_server(http_01_port):
    with misc.create_tcp_server(http_01_port) as webroot:
        yield webroot


@pytest.fixture
def tls_sni_01_server(tls_sni_01_port):
    with misc.create_tcp_server(tls_sni_01_port) as webroot:
        yield webroot


@pytest.fixture
def hook_probe():
    probe = tempfile.mkstemp()
    try:
        yield probe[1]
    finally:
        os.unlink(probe[1])
