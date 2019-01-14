"""DNS Authenticator for Linode."""
import logging

import zope.interface
from lexicon.providers import linode

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://manager.linode.com/profile/api'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Linode

    This Authenticator uses the Linode API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Linode for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=1200)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Linode credentials INI file',
            {
                'key': 'API key for Linode account, obtained from {0}'.format(API_KEY_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_linode_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_linode_client().del_txt_record(domain, validation_name, validation)

    def _get_linode_client(self):
        return _LinodeLexiconClient(self.credentials.conf('key'))


class _LinodeLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Linode API.
    """

    def __init__(self, api_key):
        super(_LinodeLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('linode', {}, {
            'auth_token': api_key,
        })

        self.provider = linode.Provider(config)

    def _handle_general_error(self, e, domain_name):
        if not str(e).startswith('Domain not found'):
            return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                      .format(domain_name, e))

