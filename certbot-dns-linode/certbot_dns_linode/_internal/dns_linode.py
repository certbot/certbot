"""DNS Authenticator for Linode."""
import logging
import re

from lexicon.providers import linode
from lexicon.providers import linode4
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://manager.linode.com/profile/api'
API_KEY_URL_V4 = 'https://cloud.linode.com/profile/tokens'

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
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=120)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Linode credentials INI file',
            {
                'key': 'API key for Linode account, obtained from {0} or {1}'
                        .format(API_KEY_URL, API_KEY_URL_V4)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_linode_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_linode_client().del_txt_record(domain, validation_name, validation)

    def _get_linode_client(self):
        api_key = self.credentials.conf('key')
        api_version = self.credentials.conf('version')
        if api_version == '':
            api_version = None

        if not api_version:
            api_version = 3

            # Match for v4 api key
            regex_v4 = re.compile('^[0-9a-f]{64}$')
            regex_match = regex_v4.match(api_key)
            if regex_match:
                api_version = 4
        else:
            api_version = int(api_version)

        return _LinodeLexiconClient(api_key, api_version)


class _LinodeLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Linode API.
    """

    def __init__(self, api_key, api_version):
        super(_LinodeLexiconClient, self).__init__()

        self.api_version = api_version

        if api_version == 3:
            config = dns_common_lexicon.build_lexicon_config('linode', {}, {
                'auth_token': api_key,
            })

            self.provider = linode.Provider(config)
        elif api_version == 4:
            config = dns_common_lexicon.build_lexicon_config('linode4', {}, {
                'auth_token': api_key,
            })

            self.provider = linode4.Provider(config)
        else:
            raise errors.PluginError('Invalid api version specified: {0}. (Supported: 3, 4)'
                                     .format(api_version))

    def _handle_general_error(self, e, domain_name):
        if not str(e).startswith('Domain not found'):
            return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                      .format(domain_name, e))
        return None
