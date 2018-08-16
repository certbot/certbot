"""DNS Authenticator for netcup."""
import nc_dnsapi
import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common

CCP_API_URL = 'https://www.netcup-wiki.de/wiki/CCP_API'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for netcup

    This Authenticator uses the netcup API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using netcup for '
                   'DNS).')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='netcup credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the netcup API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'netcup credentials INI file',
            {
                'customer-id': 'customer ID associated with netcup account',
                'api-key': 'API key for CCP API, see {0}'.format(CCP_API_URL),
                'api-password': 'API key for CCP API, see {0}'.format(CCP_API_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        with self._get_netcup_client() as api:
            api.add_dns_record(domain, _make_record(
                domain, validation_name, validation))

    def _cleanup(self, domain, validation_name, validation):
        with self._get_netcup_client() as api:
            record = api.dns_record(domain, _make_record(
                domain, validation_name, validation))
            api.delete_dns_record(domain, record)

    def _get_netcup_client(self):
        credentials = self.credentials.conf
        return nc_dnsapi.Client(
            credentials('customer-id'),
            credentials('api-key'),
            credentials('api-password'))


def _make_record(domain, validation_name, validation):
    suffix = '.' + domain
    if validation_name.endswith(suffix):
        validation_name = validation_name[:-len(suffix)]
    return nc_dnsapi.DNSRecord(
        hostname=validation_name,
        type='TXT',
        destination=validation)
