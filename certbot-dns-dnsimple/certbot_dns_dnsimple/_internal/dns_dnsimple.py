"""DNS Authenticator for DNSimple DNS."""
import logging
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional

from lexicon.providers import dnsimple
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dnsimple.com/user'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DNSimple

    This Authenticator uses the DNSimple v2 API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using DNSimple for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='DNSimple credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DNSimple API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'DNSimple credentials INI file',
            {
                'token': 'User access token for DNSimple v2 API. (See {0}.)'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnsimple_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnsimple_client().del_txt_record(domain, validation_name, validation)

    def _get_dnsimple_client(self) -> "_DNSimpleLexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _DNSimpleLexiconClient(cast(str, self.credentials.conf('token')), self.ttl)


class _DNSimpleLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the DNSimple via Lexicon.
    """

    def __init__(self, token: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('dnssimple', {
            'ttl': ttl,
        }, {
            'auth_token': token,
        })

        self.provider = dnsimple.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> errors.PluginError:
        hint = None
        if str(e).startswith('401 Client Error: Unauthorized for url:'):
            hint = 'Is your API token value correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier for {domain_name}: '
                                  f'{e}.{hint_disp}')
