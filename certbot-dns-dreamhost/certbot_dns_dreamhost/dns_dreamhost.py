"""DNS Authenticator for Dreamhost."""
import logging

import zope.interface
from lexicon.providers import dreamhost

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://panel.dreamhost.com/?tree=home.api'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Dreamhost

    This Authenticator uses the Dreamhost API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Dreamhost for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=1200)
        add('credentials', help='Dreamhost credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Dreamhost API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Dreamhost credentials INI file',
            {
                'key': 'API key for Dreamhost account, obtained from {0}'
                .format(API_KEY_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_dreamhost_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dreamhost_client().del_txt_record(domain, validation_name, validation)

    def _get_dreamhost_client(self):
        api_key = self.credentials.conf('key')

        return _DreamhostLexiconClient(api_key)


class _DreamhostLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Dreamhost API.
    """

    def __init__(self, api_key):
        super(_DreamhostLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('dreamhost', {}, {
            'auth_token': api_key,
        })

        self.provider = dreamhost.Provider(config)

    def _handle_general_error(self, e, domain_name):
        if not str(e).startswith('Domain not found'):
            return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                      .format(domain_name, e))
        return None
