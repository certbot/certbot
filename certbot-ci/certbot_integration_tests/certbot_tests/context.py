"""Module to handle the context of integration tests."""
import os
import shutil
import subprocess
import sys
import tempfile
from distutils.version import LooseVersion

from certbot_integration_tests.utils import misc


class IntegrationTestsContext(object):
    """General fixture describing a certbot integration tests context"""
    def __init__(self, request):
        self.request = request

        if hasattr(request.config, 'slaveinput'):  # Worker node
            self.worker_id = request.config.slaveinput['slaveid']
            acme_xdist = request.config.slaveinput['acme_xdist']
        else:  # Primary node
            self.worker_id = 'primary'
            acme_xdist = request.config.acme_xdist

        self.acme_server =acme_xdist['acme_server']
        self.directory_url = acme_xdist['directory_url']
        self.tls_alpn_01_port = acme_xdist['https_port'][self.worker_id]
        self.http_01_port = acme_xdist['http_port'][self.worker_id]
        self.other_port = acme_xdist['other_port'][self.worker_id]
        # Challtestsrv REST API, that exposes entrypoints to register new DNS entries,
        # is listening on challtestsrv_port.
        self.challtestsrv_port = acme_xdist['challtestsrv_port']

        # Certbot version does not depend on the test context. But getting its value requires
        # calling certbot from a subprocess. Since it will be called a lot of times through
        # _common_test_no_force_renew, we cache its value as a member of the fixture context.
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
        ).format(sys.executable, self.challtestsrv_port)
        self.manual_dns_cleanup_hook = (
            '{0} -c "import os; import requests; import json; '
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN'))}}; "
            "request = requests.post('http://localhost:{1}/clear-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_port)

    def cleanup(self):
        """Cleanup the integration test context."""
        shutil.rmtree(self.workspace)

    def _common_test_no_force_renew(self, args):
        """
        Base command to execute certbot in a distributed integration test context,
        not renewing certificates by default.
        """
        new_environ = os.environ.copy()
        new_environ['TMPDIR'] = self.workspace

        additional_args = []
        if self.certbot_version >= LooseVersion('0.30.0'):
            additional_args.append('--no-random-sleep-on-renew')

        command = [
            'certbot',
            '--server', self.directory_url,
            '--no-verify-ssl',
            '--http-01-port', str(self.http_01_port),
            '--https-port', str(self.tls_alpn_01_port),
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

    def _common_test(self, args):
        """
        Base command to execute certbot in a distributed integration test context,
        renewing certificates by default.
        """
        command = ['--renew-by-default']
        command.extend(args)
        return self._common_test_no_force_renew(command)

    def certbot_no_force_renew(self, args):
        """
        Execute certbot with given args, not renewing certificates by default.
        :param args: args to pass to certbot
        :return: output of certbot execution
        """
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return self._common_test_no_force_renew(command)

    def certbot(self, args):
        """
        Execute certbot with given args, renewing certificates by default.
        :param args: args to pass to certbot
        :return: output of certbot execution
        """
        command = ['--renew-by-default']
        command.extend(args)
        return self.certbot_no_force_renew(command)

    def get_domain(self, subdomain='le'):
        """
        Generate a certificate domain name suitable for distributed certbot integration tests.
        This is a requirement to let the distribution know how to redirect the challenge check
        from the ACME server to the relevant pytest-xdist worker. This resolution is done by
        appending the pytest worker id to the subdomain, using this pattern:
        {subdomain}.{worker_id}.wtf
        :param subdomain: the subdomain to use in the generated domain (default 'le')
        :return: the well-formed domain suitable for redirection on 
        """
        return '{0}.{1}.wtf'.format(subdomain, self.worker_id)
