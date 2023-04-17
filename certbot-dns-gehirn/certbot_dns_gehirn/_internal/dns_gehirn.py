"""DNS Authenticator for Gehirn Infrastructure Service DNS."""
import logging
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional

from lexicon.providers import gehirn
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DASHBOARD_URL = "https://gis.gehirn.jp/"


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Gehirn Infrastructure Service DNS

    This Authenticator uses the Gehirn Infrastructure Service API to fulfill
    a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record ' + \
                  '(if you are using Gehirn Infrastructure Service for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Gehirn Infrastructure Service credentials file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Gehirn Infrastructure Service API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Gehirn Infrastructure Service credentials file',
            {
                'api-token': 'API token for Gehirn Infrastructure Service ' + \
                             'API obtained from {0}'.format(DASHBOARD_URL),
                'api-secret': 'API secret for Gehirn Infrastructure Service ' + \
                              'API obtained from {0}'.format(DASHBOARD_URL),
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_gehirn_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_gehirn_client().del_txt_record(domain, validation_name, validation)

    def _get_gehirn_client(self) -> "_GehirnLexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _GehirnLexiconClient(
            cast(str, self.credentials.conf('api-token')),
            cast(str, self.credentials.conf('api-secret')),
            self.ttl
        )


class _GehirnLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Gehirn Infrastructure Service via Lexicon.
    """

    def __init__(self, api_token: str, api_secret: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('gehirn', {
            'ttl': ttl,
        }, {
            'auth_token': api_token,
            'auth_secret': api_secret,
        })

        self.provider = gehirn.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:')):
            return None  # Expected errors when zone name guess is wrong
        return super()._handle_http_error(e, domain_name)
