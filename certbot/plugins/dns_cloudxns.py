"""DNS Authenticator for CloudXNS DNS."""
import logging

import zope.interface

from certbot import interfaces

from certbot.plugins import dns_common

from lexicon.providers import cloudxns

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://www.cloudxns.net/en/AccountManage/apimanage.html'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS  Authenticator for CloudXNS DNS

    This Authenticator uses the CloudXNS DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using CloudXNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=20)
        add('api-key', help='API key for CloudXNS account. (See {0}.)'.format(ACCOUNT_URL))
        add('secret-key', help='Secret key for CloudXNS account. (See {0}.)'.format(ACCOUNT_URL))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the CloudXNS API.'

    def _setup_credentials(self):
        self._configure('api-key', 'CloudXNS API key')
        self._configure('secret-key', 'CloudXNS secret key')

    def _perform(self, domain, validation_name, validation):
        self._get_cloudxns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_cloudxns_client().del_txt_record(domain, validation_name, validation)

    def _get_cloudxns_client(self):
        return _CloudXNSLexiconClient(self.conf('api-key'), self.conf('secret-key'), self.ttl)


class _CloudXNSLexiconClient(dns_common.LexiconClient):
    """
    Encapsulates all communication with the CloudXNS via Lexicon.
    """

    def __init__(self, api_key, secret_key, ttl):
        self.provider = cloudxns.Provider({
            'auth_username': api_key,
            'auth_token': secret_key,
            'ttl': ttl,
        })

    def determine_error_hint(self, e):
        if str(e).startswith('400 Client Error:'):
            return 'Are your API key and Secret key values correct?'

        return None
