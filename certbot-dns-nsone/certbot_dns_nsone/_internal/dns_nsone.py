"""DNS Authenticator for NS1 DNS."""
import logging
from typing import Any
from collections.abc import Callable
from typing import Optional

from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://my.nsone.net/#/account/settings'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """
    DNS Authenticator for NS1
    This Authenticator uses the NS1 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using NS1 for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('api-key',
                                  f'API key for NS1 API, obtained from {ACCOUNT_URL}',
                                  'auth_token')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='NS1 credentials file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the NS1 API.'

    @property
    def _provider_name(self) -> str:
        return 'nsone'

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:') or
                                      str(e).startswith("400 Client Error: Bad Request for url:")):
            return None  # Expected errors when zone name guess is wrong
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your API key correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier: {e}.{hint_disp}')
