"""DNS Authenticator for LuaDNS DNS."""
import logging

import zope.interface
from lexicon.providers import luadns

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://api.luadns.com/settings'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for LuaDNS

    This Authenticator uses the LuaDNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using LuaDNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='LuaDNS credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the LuaDNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'LuaDNS credentials INI file',
            {
                'email': 'email address associated with LuaDNS account',
                'token': 'API token for LuaDNS account, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_luadns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_luadns_client().del_txt_record(domain, validation_name, validation)

    def _get_luadns_client(self):
        return _LuaDNSLexiconClient(self.credentials.conf('email'),
                                    self.credentials.conf('token'),
                                    self.ttl)


class _LuaDNSLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the LuaDNS via Lexicon.
    """

    def __init__(self, email, token, ttl):
        super(_LuaDNSLexiconClient, self).__init__()

        self.provider = luadns.Provider({
            'provider_name': 'luadns',
            'auth_username': email,
            'auth_token': token,
            'ttl': ttl,
        })

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Are your email and API token values correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
