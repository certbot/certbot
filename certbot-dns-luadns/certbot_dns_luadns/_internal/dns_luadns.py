"""DNS Authenticator for LuaDNS DNS."""
import logging
from typing import Any
from typing import Callable

from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://api.luadns.com/settings'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for LuaDNS

    This Authenticator uses the LuaDNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using LuaDNS for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('email',
                                  'email address associated with LuaDNS account',
                                  'auth_username')
        self._add_provider_option('token',
                                  f'API token for LuaDNS account, obtained from {ACCOUNT_URL}',
                                  'auth_token')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='LuaDNS credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the LuaDNS API.'

    @property
    def _provider_name(self) -> str:
        return 'luadns'
