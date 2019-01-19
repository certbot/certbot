import os
import tempfile
import subprocess
import shutil
import sys
from distutils.version import LooseVersion

import pytest

from certbot_integration_tests.utils import misc


@pytest.fixture
def worker_id(request):
    if hasattr(request.config, 'slaveinput'):
        return request.config.slaveinput['slaveid']
    else:
        return 'master'


@pytest.fixture
def acme_url(request, worker_id):
    return request.config.acme_xdist['directory_url']


@pytest.fixture
def tls_sni_01_port(request, worker_id):
    return request.config.acme_xdist['https_port'][worker_id]


@pytest.fixture
def http_01_port(request, worker_id):
    return request.config.acme_xdist['http_port'][worker_id]


@pytest.fixture
def challsrvtest_mgt_port(request, worker_id):
    return request.config.acme_xdist['challtestsrv_port']


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


@pytest.fixture(scope='session')
def certbot_version():
    output = subprocess.check_output(['certbot', '--version'], universal_newlines=True)
    # Typical response is: output = 'certbot 0.31.0.dev0'
    #version_str = output.split(' ')[1]
    return LooseVersion('0.31.0.dev0')


@pytest.fixture
def certbot_test_no_force_renew(workspace, config_dir, acme_url,
                                http_01_port, tls_sni_01_port,
                                certbot_version, capsys):
    new_environ = os.environ.copy()
    new_environ['TMPDIR'] = workspace

    additional_args = []
    if certbot_version >= LooseVersion('0.30.0'):
        additional_args.append('--no-random-sleep-on-renew')

    def func(args):
        command = [
            'certbot',
            '--server', acme_url,
            '--no-verify-ssl',
            '--tls-sni-01-port', str(tls_sni_01_port),
            '--http-01-port', str(http_01_port),
            '--manual-public-ip-logging-ok',
            '--config-dir', config_dir,
            '--work-dir', os.path.join(workspace, 'work'),
            '--logs-dir', os.path.join(workspace, 'logs'),
            '--non-interactive',
            '--no-redirect',
            '--agree-tos',
            '--register-unsafely-without-email',
            '--debug',
            '-vv'
        ]

        command.extend(args)
        command.extend(additional_args)

        print('Invoke command:\n{0}'.format(subprocess.list2cmdline(command)))
        return subprocess.check_output(command, universal_newlines=True,
                                       cwd=workspace, env=new_environ)

    return func


@pytest.fixture
def certbot_test(certbot_test_no_force_renew):
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


@pytest.fixture
def manual_http_auth_hook(http_01_server):
    return (
        '{0} -c "import os; '
        "challenge_dir = os.path.join('{1}', '.well-known/acme-challenge'); "
        'os.makedirs(challenge_dir); '
        "challenge_file = os.path.join(challenge_dir, os.environ.get('CERTBOT_TOKEN')); "
        "open(challenge_file, 'w').write(os.environ.get('CERTBOT_VALIDATION')); "
        '"'
    ).format(sys.executable, http_01_server)


@pytest.fixture
def manual_http_cleanup_hook(http_01_server):
    return (
        '{0} -c "import os; import shutil; '
        "well_known = os.path.join('{1}', '.well-known'); "
        'shutil.rmtree(well_known); '
        '"'
    ).format(sys.executable, http_01_server)


@pytest.fixture
def manual_dns_auth_hook(challsrvtest_mgt_port):
    return (
        '{0} -c "import os; import requests; import json; '
        "assert not os.environ.get('CERTBOT_DOMAIN').startswith('fail'); "
        "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN')),"
        "'value':os.environ.get('CERTBOT_VALIDATION')}}; "
        "request = requests.post('http://localhost:{1}/set-txt', data=json.dumps(data)); "
        "request.raise_for_status(); "
        '"'
    ).format(sys.executable, challsrvtest_mgt_port)


@pytest.fixture
def manual_dns_cleanup_hook(challsrvtest_mgt_port):
    return (
        '{0} -c "import os; import requests; import json; '
        "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN'))}}; "
        "request = requests.post('http://localhost:{1}/clear-txt', data=json.dumps(data)); "
        "request.raise_for_status(); "
        '"'
    ).format(sys.executable, challsrvtest_mgt_port)
