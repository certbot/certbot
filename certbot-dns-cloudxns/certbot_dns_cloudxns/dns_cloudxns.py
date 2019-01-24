"""DNS Authenticator for CloudXNS DNS."""
import logging

import zope.interface
from lexicon.providers import cloudxns

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://www.cloudxns.net/en/AccountManage/apimanage.html'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for CloudXNS DNS

    This Authenticator uses the CloudXNS DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using CloudXNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='CloudXNS credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the CloudXNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'CloudXNS credentials INI file',
            {
                'api-key': 'API key for CloudXNS account, obtained from {0}'.format(ACCOUNT_URL),
                'secret-key': 'Secret key for CloudXNS account, obtained from {0}'
                              .format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_cloudxns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_cloudxns_client().del_txt_record(domain, validation_name, validation)

    def _get_cloudxns_client(self):
        return _CloudXNSLexiconClient(self.credentials.conf('api-key'),
                                      self.credentials.conf('secret-key'),
                                      self.ttl)


class _CloudXNSLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the CloudXNS via Lexicon.
    """

    def __init__(self, api_key, secret_key, ttl):
        super(_CloudXNSLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('cloudxns', {
            'ttl': ttl,
        }, {
            'auth_username': api_key,
            'auth_token': secret_key,
        })

        self.provider = cloudxns.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Are your API key and Secret key values correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
