"""DNS Authenticator for NS1 DNS."""
import logging

import zope.interface
from lexicon.providers import nsone

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://my.nsone.net/#/account/settings'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for NS1

    This Authenticator uses the NS1 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using NS1 for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='NS1 credentials file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the NS1 API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'NS1 credentials file',
            {
                'api-key': 'API key for NS1 API, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_nsone_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_nsone_client().del_txt_record(domain, validation_name, validation)

    def _get_nsone_client(self):
        return _NS1LexiconClient(self.credentials.conf('api-key'), self.ttl)


class _NS1LexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the NS1 via Lexicon.
    """

    def __init__(self, api_key, ttl):
        super(_NS1LexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('nsone', {
            'ttl': ttl,
        }, {
            'auth_token': api_key,
        })

        self.provider = nsone.Provider(config)

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:') or \
                                      str(e).startswith("400 Client Error: Bad Request for url:")):
            return  # Expected errors when zone name guess is wrong
        else:
            hint = None
            if str(e).startswith('401 Client Error: Unauthorized for url:'):
                hint = 'Is your API key correct?'

            return errors.PluginError('Error determining zone identifier: {0}.{1}'
                                      .format(e, ' ({0})'.format(hint) if hint else ''))
