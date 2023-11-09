"""DNS Authenticator for DNSimple DNS."""
import logging
from typing import Any
from typing import Callable

from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dnsimple.com/user'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for DNSimple

    This Authenticator uses the DNSimple v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using DNSimple for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('token',
                                  f'User access token for DNSimple v2 API. (See {ACCOUNT_URL}.)',
                                  'auth_token')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='DNSimple credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNSimple API.'

    @property
    def _provider_name(self) -> str:
        return 'dnsimple'
