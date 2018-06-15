"""DNS Authenticator for Yandex DNS."""
import logging

import zope.interface
from lexicon.providers import yandex

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://tech.yandex.com/domain/doc/concepts/access-docpage/#access-admin'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Yandex

    This Authenticator uses the Yandex v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Yandex for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Yandex credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Yandex API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Yandex credentials INI file',
            {
                'token': 'User access token for Yandex v2 API. (See {0}.)'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_yandex_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_yandex_client().del_txt_record(domain, validation_name, validation)

    def _get_yandex_client(self):
        return _YandexLexiconClient(self.credentials.conf('token'), self.ttl)


class _YandexLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Yandex via Lexicon.
    """

    def __init__(self, token, ttl):
        super(_YandexLexiconClient, self).__init__()

        self.provider = yandex.Provider({
            'auth_token': token,
            'ttl': ttl,
        })

    def _handle_general_error(self, e, domain_name):
        if str(e) == '':
            return

        hint = None
        if str(e).startswith('No domain found'):
            hint = 'Is your API token value correct?'

        return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
