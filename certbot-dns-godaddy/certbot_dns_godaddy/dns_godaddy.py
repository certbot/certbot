"""DNS Authenticator for Godaddy."""
import logging

import zope.interface
from lexicon.providers import godaddy

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://developer.godaddy.com/keys'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Godaddy

    This Authenticator uses the Godaddy API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Godaddy for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=120)
        add('credentials', help='Godaddy credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Godaddy API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Godaddy credentials INI file',
            {
                'key': 'API key for Godaddy account, obtained from {0}'
                        .format(API_KEY_URL),
                'secret': 'API secret for Godaddy account, obtained with API key'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_godaddy_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_godaddy_client().del_txt_record(domain, validation_name, validation)

    def _get_godaddy_client(self):
        api_key = self.credentials.conf('key')
        key_secret = self.credentials.conf('secret')
        return _GodaddyLexiconClient(api_key, key_secret)


class _GodaddyLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Godaddy API.
    """

    def __init__(self, api_key, key_secret):
        super(_GodaddyLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('godaddy', {}, {
            'auth_key': api_key,
            'auth_secret': key_secret
        })

        self.provider = godaddy.Provider(config)

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong

        return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                  .format(domain_name, e))
