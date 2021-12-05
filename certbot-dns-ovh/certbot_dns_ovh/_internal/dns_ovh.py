"""DNS Authenticator for OVH DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from lexicon.providers import ovh
from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://eu.api.ovh.com/createToken/ or https://ca.api.ovh.com/createToken/'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for OVH

    This Authenticator uses the OVH API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using OVH for DNS).'
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='OVH credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the OVH API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'OVH credentials INI file',
            {
                'endpoint': 'OVH API endpoint (ovh-eu or ovh-ca)',
                'application-key': 'Application key for OVH API, obtained from {0}'
                .format(TOKEN_URL),
                'application-secret': 'Application secret for OVH API, obtained from {0}'
                .format(TOKEN_URL),
                'consumer-key': 'Consumer key for OVH API, obtained from {0}'
                .format(TOKEN_URL),
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_ovh_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_ovh_client().del_txt_record(domain, validation_name, validation)

    def _get_ovh_client(self) -> "_OVHLexiconClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _OVHLexiconClient(
            self.credentials.conf('endpoint'),
            self.credentials.conf('application-key'),
            self.credentials.conf('application-secret'),
            self.credentials.conf('consumer-key'),
            self.ttl
        )


class _OVHLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the OVH API via Lexicon.
    """

    def __init__(self, endpoint: str, application_key: str, application_secret: str,
                 consumer_key: str, ttl: int) -> None:
        super().__init__()

        config = dns_common_lexicon.build_lexicon_config('ovh', {
            'ttl': ttl,
        }, {
            'auth_entrypoint': endpoint,
            'auth_application_key': application_key,
            'auth_application_secret': application_secret,
            'auth_consumer_key': consumer_key,
        })

        self.provider = ovh.Provider(config)

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> errors.PluginError:
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Is your Application Secret value correct?'
        if str(e).startswith('403 Client Error:'):
            hint = 'Are your Application Key and Consumer Key values correct?'

        hint_disp = f' ({hint})' if hint else ''

        return errors.PluginError(f'Error determining zone identifier for {domain_name}: '
                                  f'{e}.{hint_disp}')

    def _handle_general_error(self, e: Exception, domain_name: str) -> Optional[errors.PluginError]:
        if domain_name in str(e) and str(e).endswith('not found'):
            return None

        return super()._handle_general_error(e, domain_name)
