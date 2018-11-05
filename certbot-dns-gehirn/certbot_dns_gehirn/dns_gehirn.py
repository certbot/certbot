"""DNS Authenticator for Gehirn Infrastracture Service DNS."""
import logging

import zope.interface
from lexicon.providers import gehirn

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

DASHBOARD_URL = "https://gis.gehirn.jp/"

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Gehirn Infrastracture Service DNS

    This Authenticator uses the Gehirn Infrastracture Service API to fulfill
    a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Gehirn Infrastracture Service for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Gehirn Infrastracture Service credentials file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Gehirn Infrastracture Service API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Gehirn Infrastracture Service credentials file',
            {
                'api-token': 'API token for Gehirn Infrastracture Service ' + \
                             'API obtained from {0}'.format(DASHBOARD_URL),
                'api-secret': 'API secret for Gehirn Infrastracture Service ' + \
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
    Encapsulates all communication with the Gehirn Infrastracture Service via Lexicon.
    """

    def __init__(self, api_token, api_secret, ttl):
        super(_GehirnLexiconClient, self).__init__()

        self.provider = gehirn.Provider({
            'provider_name': 'gehirn',
            'auth_token': api_token,
            'auth_secret': api_secret,
            'ttl': ttl,
        })

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return  # Expected errors when zone name guess is wrong
        return super(_GehirnLexiconClient, self)._handle_http_error(e, domain_name)
