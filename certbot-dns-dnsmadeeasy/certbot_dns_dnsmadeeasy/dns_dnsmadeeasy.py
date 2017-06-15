"""DNS Authenticator for DNS Made Easy DNS."""
import logging

import zope.interface
from lexicon.providers import dnsmadeeasy

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://cp.dnsmadeeasy.com/account/info'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNS Made Easy

    This Authenticator uses the DNS Made Easy API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using DNS Made Easy for '
                   'DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='DNS Made Easy credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNS Made Easy API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'DNS Made Easy credentials INI file',
            {
                'api-key': 'API key for DNS Made Easy account, obtained from {0}'
                           .format(ACCOUNT_URL),
                'secret-key': 'Secret key for DNS Made Easy account, obtained from {0}'
                              .format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_dnsmadeeasy_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dnsmadeeasy_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsmadeeasy_client(self):
        return _DNSMadeEasyLexiconClient(self.credentials.conf('api-key'),
                                         self.credentials.conf('secret-key'),
                                         self.ttl)


class _DNSMadeEasyLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the DNS Made Easy via Lexicon.
    """

    def __init__(self, api_key, secret_key, ttl):
        super(_DNSMadeEasyLexiconClient, self).__init__()

        self.provider = dnsmadeeasy.Provider({
            'auth_username': api_key,
            'auth_token': secret_key,
            'ttl': ttl,
        })

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and str(e).startswith('404 Client Error: Not Found for url:'):
            return

        hint = None
        if str(e).startswith('403 Client Error: Forbidden for url:'):
            hint = 'Are your API key and Secret key values correct?'

        return errors.PluginError('Error determining zone identifier: {0}.{1}'
                                  .format(e, ' ({0})'.format(hint) if hint else ''))
