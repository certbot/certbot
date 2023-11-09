"""DNS Authenticator for DNS Made Easy DNS."""
import logging
from typing import Any
from typing import Callable

from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://cp.dnsmadeeasy.com/account/info'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for DNS Made Easy

    This Authenticator uses the DNS Made Easy API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using DNS Made Easy for '
                   'DNS).')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('api-key',
                                  'API key for DNS Made Easy account, '
                                  f'obtained from {ACCOUNT_URL}',
                                  'auth_username')
        self._add_provider_option('secret-key',
                                  'Secret key for DNS Made Easy account, '
                                  f'obtained from {ACCOUNT_URL}',
                                  'auth_token')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='DNS Made Easy credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNS Made Easy API.'

    @property
    def _provider_name(self) -> str:
        return 'dnsmadeeasy'
