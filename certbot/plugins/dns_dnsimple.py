"""DNS Authenticator for DNSimple DNS."""
import logging

import zope.interface

from certbot import interfaces

from certbot.plugins import dns_common

from lexicon.providers import dnsimple

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dnsimple.com/user'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSimple

    This Authenticator uses the DNSimple v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using DNSimple for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('token', help='User access token for DNSimple v2 API. (See {0}.)'.format(ACCOUNT_URL))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNSimple API.'

    def _setup_credentials(self):
        self._configure('token', 'User access token (for v2 API)')

    def _perform(self, domain, validation_name, validation):
        self._get_dnsimple_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_dnsimple_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsimple_client(self):
        return _DNSimpleLexiconClient(self.conf('token'), self.ttl)


class _DNSimpleLexiconClient(dns_common.LexiconClient):
    """
    Encapsulates all communication with the DNSimple via Lexicon.
    """

    def __init__(self, token, ttl):
        self.provider = dnsimple.Provider({
            'auth_token': token,
            'ttl': ttl,
        })

    def determine_error_hint(self, e):
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            return 'Is your API token value correct?'

        return None
