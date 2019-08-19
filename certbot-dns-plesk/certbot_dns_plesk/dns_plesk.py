"""DNS Authenticator for Plesk DNS."""
import logging

import zope.interface
from lexicon.providers import plesk

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Plesk

    This Authenticator uses the Plesk API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Plesk (external access) for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Plesk credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Plesk API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Plesk credentials INI file',
            {
                'username': 'Username for Plesk API.',
                'password': 'Password for Plesk API.',
                'pleskserver': 'Url of the host https://hostname:port',
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_plesk_client(domain).add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_plesk_client(domain).del_txt_record(domain, validation_name, validation)

    def _get_plesk_client(self,domain):
        return _PleskLexiconClient(self.credentials.conf('pleskserver'), 
                 self.credentials.conf('username'),
                 self.credentials.conf('password'),
                 domain)


class _PleskLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Plesk via Lexicon.
    """

    def __init__(self, pleskserver, username, password, domain ):
        super(_PleskLexiconClient, self).__init__()

        self.provider = plesk.Provider({
            'auth_username': username,
            'auth_password': password,
            'plesk_server': pleskserver,
            'domain': domain,
        })

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your pleskserver & authentication info correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
