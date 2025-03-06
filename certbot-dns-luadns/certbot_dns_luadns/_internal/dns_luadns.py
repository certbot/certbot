"""DNS Authenticator for LuaDNS DNS."""
from collections.abc import Callable
import logging
from typing import Any

from requests import HTTPError

from certbot import errors
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

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> errors.PluginError:
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Are your email and API token values correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier for {domain_name}: '
                                  f'{e}.{hint_disp}')
