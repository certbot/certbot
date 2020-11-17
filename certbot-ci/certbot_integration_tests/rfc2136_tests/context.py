from contextlib import contextmanager
from pytest import skip
from pkg_resources import resource_filename
import tempfile

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.utils import certbot_call


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    """Integration test context for certbot-dns-rfc2136"""
    def __init__(self, request):
        super(IntegrationTestsContext, self).__init__(request)

        self.request = request

        self._dns_xdist = None
        if hasattr(request.config, 'slaveinput'):  # Worker node
            self._dns_xdist = request.config.slaveinput['dns_xdist']
        else:  # Primary node
            self._dns_xdist = request.config.dns_xdist

    def certbot_test_rfc2136(self, args):
        """
        Main command to execute certbot using the RFC2136 DNS authenticator.
        :param list args: list of arguments to pass to Certbot
        """
        command = ['--authenticator', 'dns-rfc2136', '--dns-rfc2136-propagation-seconds', '2']
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, force_renew=True)

    @contextmanager
    def rfc2136_credentials(self, label='default'):
        # type: (str) -> str
        """
        Produces the contents of a certbot-dns-rfc2136 credentials file.
        :param str label: which RFC2136 credential to use
        :yields: Path to credentials file
        :rtype: str
        """
        src_file = resource_filename('certbot_integration_tests',
                                     'assets/bind-config/rfc2136-credentials-{}.ini.tpl'
                                     .format(label))
        contents = None

        with open(src_file, 'r') as f:
            contents = f.read().format(
                server_address=self._dns_xdist['address'],
                server_port=self._dns_xdist['port']
            )

        with tempfile.NamedTemporaryFile('w+', prefix='rfc2136-creds-{}'.format(label),
                                         suffix='.ini', dir=self.workspace) as f:
            f.write(contents)
            f.flush()
            yield f.name

    def skip_if_no_bind9_server(self):
        """Skips the test if there was no RFC2136-capable DNS server configured
        in the test environment"""
        if not self._dns_xdist:
            skip('No RFC2136-capable DNS server is configured')
