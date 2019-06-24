"""Module to handle the context of integration tests."""
import os
import shutil
import subprocess
import sys
import tempfile

import requests

from certbot_integration_tests.utils import certbot_call, misc, ocsp_server
from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT


class IntegrationTestsContext(object):
    """General fixture describing a certbot integration tests context"""
    def __init__(self, request):
        self._subprocesses = []
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
        for process in self._subprocesses:
            process.terminate()
            process.wait()
        shutil.rmtree(self.workspace)

    def certbot(self, args, force_renew=True):
        """
        Execute certbot with given args, not renewing certificates by default.
        :param args: args to pass to certbot
        :param force_renew: set to False to not renew by default
        :return: output of certbot execution
        """
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, force_renew=force_renew)

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

    def mock_ocsp_server(self, cert_path, ocsp_status):
        """
        Start a mock OCSP server to check OSCP statuses with Pebble.
        :param cert_path: the path to the cert whose OCSP status is checked
        :param ocsp_status: the OCSP status to return
        """
        root_url = self.directory_url.replace('/dir', '')

        issuer_key_path = os.path.join(self.workspace, 'ocsp_key.pem')
        issuer_cert_path = os.path.join(self.workspace, 'ocsp_cert.pem')
        with open(issuer_key_path, 'w') as file_h:
            misc.ignore_https_warnings()
            file_h.write(requests.get(root_url + '/intermediate-key', verify=False).content)
        with open(issuer_cert_path, 'w') as file_h:
            misc.ignore_https_warnings()
            file_h.write(requests.get(root_url + '/intermediate', verify=False).content)

        process = subprocess.Popen([sys.executable, ocsp_server.__file__, cert_path,
                                    issuer_cert_path, issuer_key_path, ocsp_status])
        self._subprocesses.append(process)
