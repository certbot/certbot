import os
import tempfile
import subprocess
import shutil
import sys
from distutils.version import LooseVersion

import pytest

from certbot_integration_tests.utils import misc


@pytest.fixture()
def context(request):
    integration_test_context = _IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


@pytest.fixture()
def http_01_server(context):
    with misc.create_tcp_server(context.http_01_port) as webroot:
        yield webroot


@pytest.fixture(context)
def tls_alpn_01_server(context):
    with misc.create_tcp_server(context.tls_alpn_01_port) as webroot:
        yield webroot


@pytest.fixture()
def manual_http_hooks(http_01_server):
    auth = (
        '{0} -c "import os; '
        "challenge_dir = os.path.join('{1}', '.well-known/acme-challenge'); "
        'os.makedirs(challenge_dir); '
        "challenge_file = os.path.join(challenge_dir, os.environ.get('CERTBOT_TOKEN')); "
        "open(challenge_file, 'w').write(os.environ.get('CERTBOT_VALIDATION')); "
        '"'
    ).format(sys.executable, http_01_server)
    cleanup = (
        '{0} -c "import os; import shutil; '
        "well_known = os.path.join('{1}', '.well-known'); "
        'shutil.rmtree(well_known); '
        '"'
    ).format(sys.executable, http_01_server)

    return auth, cleanup


class _IntegrationTestsContext(object):
    def __init__(self, request):
        self.request = request

        self.worker_id = request.config.slaveinput['slaveid'] if hasattr(request.config, 'slaveinput') else 'master'
        self.acme_url = request.config.acme_xdist['directory_url']
        self.tls_alpn_01_port = request.config.acme_xdist['https_port'][self.worker_id]
        self.http_01_port = request.config.acme_xdist['http_port'][self.worker_id]
        self.challtestsrv_mgt_port = request.config.acme_xdist['challtestsrv_port']

        self.certbot_version = misc.get_certbot_version()

        self.workspace = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.workspace, 'conf')
        self.hook_probe = tempfile.mkstemp(dir=self.workspace)[1]

        self.manual_dns_auth_hook = (
            '{0} -c "import os; import requests; import json; '
            "assert not os.environ.get('CERTBOT_DOMAIN').startswith('fail'); "
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN')),"
            "'value':os.environ.get('CERTBOT_VALIDATION')}}; "
            "request = requests.post('http://localhost:{1}/set-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_mgt_port)
        self.manual_dns_cleanup_hook = (
            '{0} -c "import os; import requests; import json; '
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN'))}}; "
            "request = requests.post('http://localhost:{1}/clear-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_mgt_port)

    def cleanup(self):
        shutil.rmtree(self.workspace)

    def certbot_test_no_force_renew(self, args):
        new_environ = os.environ.copy()
        new_environ['TMPDIR'] = self.workspace

        additional_args = []
        if self.certbot_version >= LooseVersion('0.30.0'):
            additional_args.append('--no-random-sleep-on-renew')

        command = [
            'certbot',
            '--server', self.acme_url,
            '--no-verify-ssl',
            '--tls-sni-01-port', str(self.tls_alpn_01_port),
            '--http-01-port', str(self.http_01_port),
            '--manual-public-ip-logging-ok',
            '--config-dir', self.config_dir,
            '--work-dir', os.path.join(self.workspace, 'work'),
            '--logs-dir', os.path.join(self.workspace, 'logs'),
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
                                       cwd=self.workspace, env=new_environ)

    def certbot_test(self, args):
        command = ['--renew-by-default']
        command.extend(args)
        self.certbot_test_no_force_renew(command)

    def common_no_force_renew(self, args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        self.certbot_test_no_force_renew(command)

    def common(self, args):
        command = ['--renew-by-default']
        command.extend(args)
        self.common_no_force_renew(command)

    def wtf(self, prefix='le'):
        return '{0}.{1}.wtf'.format(prefix, self.worker_id)
