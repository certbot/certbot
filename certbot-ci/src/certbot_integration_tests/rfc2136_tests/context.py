"""Module to handle the context of RFC2136 integration tests."""
from contextlib import contextmanager
import importlib.resources
import tempfile
from typing import Generator
from typing import Iterable
from typing import Tuple

import pytest

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.utils import certbot_call


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    """Integration test context for certbot-dns-rfc2136"""
    def __init__(self, request: pytest.FixtureRequest) -> None:
        super().__init__(request)

        self.request = request

        if hasattr(request.config, 'workerinput'):  # Worker node
            self._dns_xdist = request.config.workerinput['dns_xdist']
        else:  # Primary node
            self._dns_xdist = request.config.dns_xdist  # type: ignore[attr-defined]

    def certbot_test_rfc2136(self, args: Iterable[str]) -> Tuple[str, str]:
        """
        Main command to execute certbot using the RFC2136 DNS authenticator.
        :param list args: list of arguments to pass to Certbot
        """
        command = ['--authenticator', 'dns-rfc2136', '--dns-rfc2136-propagation-seconds', '2']
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.https_port,
            self.config_dir, self.workspace, force_renew=True)

    @contextmanager
    def rfc2136_credentials(self, label: str = 'default') -> Generator[str, None, None]:
        """
        Produces the contents of a certbot-dns-rfc2136 credentials file.
        :param str label: which RFC2136 credential to use
        :yields: Path to credentials file
        :rtype: str
        """
        src_ref_file = (importlib.resources.files('certbot_integration_tests').joinpath('assets')
                        .joinpath('bind-config').joinpath(f'rfc2136-credentials-{label}.ini.tpl'))
        with importlib.resources.as_file(src_ref_file) as src_file:
            with open(src_file, 'r') as f:
                contents = f.read().format(
                    server_address=self._dns_xdist['address'],
                    server_port=self._dns_xdist['port']
                )

        with tempfile.NamedTemporaryFile('w+', prefix='rfc2136-creds-{}'.format(label),
                                         suffix='.ini', dir=self.workspace) as fp:
            fp.write(contents)
            fp.flush()
            yield fp.name

    def skip_if_no_bind9_server(self) -> None:
        """Skips the test if there was no RFC2136-capable DNS server configured
        in the test environment"""
        if not self._dns_xdist:
            pytest.skip('No RFC2136-capable DNS server is configured')
