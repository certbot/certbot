"""DNS Authenticator for Gehirn Infrastructure Service DNS."""
import logging

from lexicon.providers import gehirn
import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

DASHBOARD_URL = "https://gis.gehirn.jp/"

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Gehirn Infrastructure Service DNS

    This Authenticator uses the Gehirn Infrastructure Service API to fulfill
    a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Gehirn Infrastructure Service for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Gehirn Infrastructure Service credentials file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Gehirn Infrastructure Service API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Gehirn Infrastructure Service credentials file',
            {
                'api-token': 'API token for Gehirn Infrastructure Service ' + \
                             'API obtained from {0}'.format(DASHBOARD_URL),
                'api-secret': 'API secret for Gehirn Infrastructure Service ' + \
                              'API obtained from {0}'.format(DASHBOARD_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_gehirn_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_gehirn_client().del_txt_record(domain, validation_name, validation)

    def _get_gehirn_client(self):
        return _GehirnLexiconClient(
            self.credentials.conf('api-token'),
            self.credentials.conf('api-secret'),
            self.ttl
        )


class _GehirnLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Gehirn Infrastructure Service via Lexicon.
    """

    def __init__(self, api_token, api_secret, ttl):
        super(_GehirnLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('gehirn', {
            'ttl': ttl,
        }, {
            'auth_token': api_token,
            'auth_secret': api_secret,
        })

        self.provider = gehirn.Provider(config)

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong
        return super(_GehirnLexiconClient, self)._handle_http_error(e, domain_name)
