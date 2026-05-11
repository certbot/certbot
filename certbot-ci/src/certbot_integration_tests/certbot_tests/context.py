"""Module to handle the context of integration tests."""
import os
import shutil
import sys
import tempfile
import textwrap
from typing import Iterable

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
        self.https_port = acme_xdist['https_port'][self.worker_id]
        self.local_ip = str(acme_xdist['local_ip'][self.worker_id])
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

        self.manual_dns_auth_hook = self.generate_dns_auth_hook('_acme-challenge', True)
        self.manual_dns_auth_hook_allow_fail = self.generate_dns_auth_hook('_acme-challenge', False)
        self.manual_dns_cleanup_hook = self.generate_dns_cleanup_hook('_acme-challenge')

        self.manual_dns_persist_auth_hook = self.generate_dns_auth_hook('_validation-persist', True)
        self.manual_dns_persist_cleanup_hook = self.generate_dns_cleanup_hook('_validation-persist')

    def generate_dns_auth_hook(self, challenge_subdomain: str, fail_on_subdomain: bool) -> str:
        """Generates a python one-liner script which sets a DNS challenge TXT record challtestsrv
        URL, and optionally fails if the subdomain starts with the word "fail" to simulate a faulty
        script"""
        script = textwrap.dedent(f"""\
            import os
            import requests
            import json
            domain = os.environ.get('CERTBOT_DOMAIN')
            {"assert not domain.startswith('fail')" if fail_on_subdomain else "# no-op"}
            validation = os.environ.get('CERTBOT_VALIDATION')
            data = {{'host':'{challenge_subdomain}.{{0}}.'.format(domain), 'value': validation}}
            request = requests.post('{self.challtestsrv_url}/set-txt', data=json.dumps(data))
            request.raise_for_status()
        """)
        return f'{sys.executable} -c "{script}"'

    def generate_dns_cleanup_hook(self, challenge_subdomain: str) -> str:
        """Generates a python one-liner script which cleans up the TXT record made by
        `generate_dns_auth_hook`"""
        script = textwrap.dedent(f"""\
            import os
            import requests
            import json
            domain = os.environ.get('CERTBOT_DOMAIN')
            data = {{'host':'{challenge_subdomain}.{{0}}.'.format(domain)}}
            request = requests.post('{self.challtestsrv_url}/clear-txt', data=json.dumps(data))
            request.raise_for_status()
        """)
        return f'{sys.executable} -c "{script}"'

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
            command, self.directory_url, self.http_01_port, self.https_port,
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
