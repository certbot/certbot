"""DNS Authenticator for CloudXNS DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional
import warnings

from lexicon.providers import cloudxns
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://www.cloudxns.net/en/AccountManage/apimanage.html'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for CloudXNS DNS

    This Authenticator uses the CloudXNS DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using CloudXNS for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "The CloudXNS authenticator is deprecated and will be removed in the "
            "next major release of Certbot. The CloudXNS DNS service is defunct and "
            "we recommend removing the plugin."
        )
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='CloudXNS credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the CloudXNS API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'CloudXNS credentials INI file',
            {
                'api-key': 'API key for CloudXNS account, obtained from {0}'.format(ACCOUNT_URL),
                'secret-key': 'Secret key for CloudXNS account, obtained from {0}'
                              .format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_cloudxns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_cloudxns_client().del_txt_record(domain, validation_name, validation)

    def _get_cloudxns_client(self) -> "_CloudXNSLexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _CloudXNSLexiconClient(self.credentials.conf('api-key'),
                                      self.credentials.conf('secret-key'),
                                      self.ttl)


class _CloudXNSLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the CloudXNS via Lexicon.
    """

    def __init__(self, api_key: str, secret_key: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('cloudxns', {
            'ttl': ttl,
        }, {
            'auth_username': api_key,
            'auth_token': secret_key,
        })

        self.provider = cloudxns.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Are your API key and Secret key values correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier for {domain_name}: '
                                  f'{e}.{hint_disp}')
