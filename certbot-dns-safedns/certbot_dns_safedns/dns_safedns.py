"""DNS Authenticator for UKFast's SafeDNS service."""
import logging

import zope.interface
from lexicon.providers import safedns

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://my.ukfast.co.uk/applications/index.php'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for UKFast's SafeDNS

    This Authenticator uses the SafeDNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using SafeDNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='SafeDNS credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the SafeDNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'SafeDNS credentials INI file',
            {
                'auth_token': 'API Application Token for SafeDNS account, obtained from {0}'
                .format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_safedns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_safedns_client().del_txt_record(domain, validation_name, validation)

    def _get_safedns_client(self):
        return _SafeDNSLexiconClient(
            self.credentials.conf('auth_token'),
            self.ttl
        )

class _SafeDNSLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with SafeDNS via Lexicon.
    """

    def __init__(self, auth_token, ttl):
        super(_SafeDNSLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('safedns', {
            'ttl': ttl,
        }, {
            'auth_token': auth_token,
        })

        self.provider = safedns.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Are your API key and Secret key values correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        if domain_name in str(e) and str(e).endswith('not found'):
            return

        super(_SafeDNSLexiconClient, self)._handle_general_error(e, domain_name)
