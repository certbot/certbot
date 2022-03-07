"""DNS Authenticator for DNS Made Easy DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from lexicon.providers import dnsmadeeasy
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://cp.dnsmadeeasy.com/account/info'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNS Made Easy

    This Authenticator uses the DNS Made Easy API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using DNS Made Easy for '
                   'DNS).')
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='DNS Made Easy credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNS Made Easy API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'DNS Made Easy credentials INI file',
            {
                'api-key': f'API key for DNS Made Easy account, obtained from {ACCOUNT_URL}',
                'secret-key': f'Secret key for DNS Made Easy account, obtained from {ACCOUNT_URL}',
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnsmadeeasy_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnsmadeeasy_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsmadeeasy_client(self) -> "_DNSMadeEasyLexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _DNSMadeEasyLexiconClient(self.credentials.conf('api-key'),
                                         self.credentials.conf('secret-key'),
                                         self.ttl)


class _DNSMadeEasyLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the DNS Made Easy via Lexicon.
    """

    def __init__(self, api_key: str, secret_key: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('dnsmadeeasy', {
            'ttl': ttl,
        }, {
            'auth_username': api_key,
            'auth_token': secret_key,
        })

        self.provider = dnsmadeeasy.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and str(e).startswith('404 Client Error: Not Found for url:'):
            return None

        hint = None
        if str(e).startswith('403 Client Error: Forbidden for url:'):
            hint = 'Are your API key and Secret key values correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier: {e}.{hint_disp}')
