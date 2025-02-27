"""DNS Authenticator for Gehirn Infrastructure Service DNS."""
import logging
from typing import Any
from collections.abc import Callable
from typing import Optional

from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

DASHBOARD_URL = "https://gis.gehirn.jp/"


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for Gehirn Infrastructure Service DNS

    This Authenticator uses the Gehirn Infrastructure Service API to fulfill
    a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Gehirn Infrastructure Service for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('api-token',
                                  'API token for Gehirn Infrastructure Service '
                                  f'API obtained from {DASHBOARD_URL}',
                                  'auth_token')
        self._add_provider_option('api-secret',
                                  'API secret for Gehirn Infrastructure Service '
                                  f'API obtained from {DASHBOARD_URL}',
                                  'auth_secret')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Gehirn Infrastructure Service credentials file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Gehirn Infrastructure Service API.'

    @property
    def _provider_name(self) -> str:
        return 'gehirn'

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong
        return super()._handle_http_error(e, domain_name)
