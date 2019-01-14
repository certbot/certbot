"""DNS Authenticator for DNSimple DNS."""
import logging

import zope.interface
from lexicon.providers import dnsimple

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dnsimple.com/user'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSimple

    This Authenticator uses the DNSimple v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using DNSimple for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='DNSimple credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNSimple API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'DNSimple credentials INI file',
            {
                'token': 'User access token for DNSimple v2 API. (See {0}.)'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_dnsimple_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dnsimple_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsimple_client(self):
        return _DNSimpleLexiconClient(self.credentials.conf('token'), self.ttl)


class _DNSimpleLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the DNSimple via Lexicon.
    """

    def __init__(self, token, ttl):
        super(_DNSimpleLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('dnssimple', {
            'ttl': ttl,
        }, {
            'auth_token': token,
        })

        self.provider = dnsimple.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your API token value correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))
