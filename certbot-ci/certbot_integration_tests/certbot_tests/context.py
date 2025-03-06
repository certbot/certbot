"""Module to handle the context of integration tests."""
from collections.abc import Iterable
import os
import shutil
import sys
import tempfile

import pytest

from certbot_integration_tests.utils import certbot_call


class IntegrationTestsContext:
    """General fixture describing a certbot integration tests context"""
    def __init__(self, request: pytest.FixtureRequest) -> None:
        self.request = request

        if hasattr(request.config, 'workerinput'):  # Worker node
            self.worker_id = request.config.workerinput['workerid']
            acme_xdist = request.config.workerinput['acme_xdist']
        else:  # Primary node
            self.worker_id = 'primary'
            acme_xdist = request.config.acme_xdist  # type: ignore[attr-defined]

        self.directory_url = acme_xdist['directory_url']
        self.tls_alpn_01_port = acme_xdist['https_port'][self.worker_id]
        self.http_01_port = acme_xdist['http_port'][self.worker_id]
        self.other_port = acme_xdist['other_port'][self.worker_id]
        # Challtestsrv REST API, that exposes entrypoints to register new DNS entries,
        # is listening on challtestsrv_url.
        self.challtestsrv_url = acme_xdist['challtestsrv_url']

        self.workspace = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.workspace, 'conf')

        probe = tempfile.mkstemp(dir=self.workspace)
        os.close(probe[0])
        self.hook_probe = probe[1]

        self.manual_dns_auth_hook = (
            '{0} -c "import os; import requests; import json; '
            "assert not os.environ.get('CERTBOT_DOMAIN').startswith('fail'); "
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN')),"
            "'value':os.environ.get('CERTBOT_VALIDATION')}}; "
            "request = requests.post('{1}/set-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_url)
        self.manual_dns_auth_hook_allow_fail = (
            '{0} -c "import os; import requests; import json; '
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN')),"
            "'value':os.environ.get('CERTBOT_VALIDATION')}}; "
            "request = requests.post('{1}/set-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_url)
        self.manual_dns_cleanup_hook = (
            '{0} -c "import os; import requests; import json; '
            "data = {{'host':'_acme-challenge.{{0}}.'.format(os.environ.get('CERTBOT_DOMAIN'))}}; "
            "request = requests.post('{1}/clear-txt', data=json.dumps(data)); "
            "request.raise_for_status(); "
            '"'
        ).format(sys.executable, self.challtestsrv_url)

    def cleanup(self) -> None:
        """Cleanup the integration test context."""
        shutil.rmtree(self.workspace)

    def certbot(self, args: Iterable[str], force_renew: bool = True) -> tuple[str, str]:
        """
        Execute certbot with given args, not renewing certificates by default.
        :param args: args to pass to certbot
        :param bool force_renew: set to False to not renew by default
        :return: stdout and stderr from certbot execution
        :rtype: Tuple of `str`
        """
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, force_renew=force_renew)

    def get_domain(self, subdomain: str = 'le') -> str:
        """
        Generate a certificate domain name suitable for distributed certbot integration tests.
        This is a requirement to let the distribution know how to redirect the challenge check
        from the ACME server to the relevant pytest-xdist worker. This resolution is done by
        appending the pytest worker id to the subdomain, using this pattern:
        {subdomain}.{worker_id}.wtf
        :param str subdomain: the subdomain to use in the generated domain (default 'le')
        :return: the well-formed domain suitable for redirection on
        :rtype: str
        """
        return '{0}.{1}.wtf'.format(subdomain, self.worker_id)
