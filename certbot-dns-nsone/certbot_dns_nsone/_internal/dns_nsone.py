"""DNS Authenticator for NS1 DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from lexicon.providers import nsone
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://my.nsone.net/#/account/settings'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for NS1

    This Authenticator uses the NS1 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using NS1 for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='NS1 credentials file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the NS1 API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'NS1 credentials file',
            {
                'api-key': 'API key for NS1 API, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_nsone_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_nsone_client().del_txt_record(domain, validation_name, validation)

    def _get_nsone_client(self) -> "_NS1LexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _NS1LexiconClient(self.credentials.conf('api-key'), self.ttl)


class _NS1LexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the NS1 via Lexicon.
    """

    def __init__(self, api_key: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('nsone', {
            'ttl': ttl,
        }, {
            'auth_token': api_key,
        })

        self.provider = nsone.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and (str(e).startswith('404 Client Error: Not Found for url:') or
                                      str(e).startswith("400 Client Error: Bad Request for url:")):
            return None  # Expected errors when zone name guess is wrong
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your API key correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier: {e}.{hint_disp}')
