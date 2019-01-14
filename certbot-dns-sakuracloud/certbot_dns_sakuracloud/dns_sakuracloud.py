"""DNS Authenticator for Sakura Cloud DNS."""
import logging

import zope.interface
from lexicon.providers import sakuracloud

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

APIKEY_URL = "https://secure.sakura.ad.jp/cloud/#!/apikey/top/"


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Sakura Cloud DNS

    This Authenticator uses the Sakura Cloud API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Sakura Cloud for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=90)
        add('credentials', help='Sakura Cloud credentials file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Sakura Cloud API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Sakura Cloud credentials file',
            {
                'api-token': \
                    'API token for Sakura Cloud API obtained from {0}'.format(APIKEY_URL),
                'api-secret': \
                    'API secret for Sakura Cloud API obtained from {0}'.format(APIKEY_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_sakuracloud_client().add_txt_record(
            domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_sakuracloud_client().del_txt_record(
            domain, validation_name, validation)

    def _get_sakuracloud_client(self):
        return _SakuraCloudLexiconClient(
            self.credentials.conf('api-token'),
            self.credentials.conf('api-secret'),
            self.ttl
        )


class _SakuraCloudLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Sakura Cloud via Lexicon.
    """

    def __init__(self, api_token, api_secret, ttl):
        super(_SakuraCloudLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('sakuracloud', {
            'ttl': ttl,
        }, {
            'auth_token': api_token,
            'auth_secret': api_secret,
        })

        self.provider = sakuracloud.Provider(config)

    def _handle_http_error(self, e, domain_name):
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return  # Expected errors when zone name guess is wrong
        return super(_SakuraCloudLexiconClient, self)._handle_http_error(e, domain_name)
