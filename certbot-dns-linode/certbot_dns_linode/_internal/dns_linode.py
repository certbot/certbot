"""DNS Authenticator for Linode."""
import logging
import re
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

from lexicon.providers import linode
from lexicon.providers import linode4

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

API_KEY_URL = 'https://manager.linode.com/profile/api'
API_KEY_URL_V4 = 'https://cloud.linode.com/profile/tokens'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Linode

    This Authenticator uses the Linode API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Linode for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 120) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Linode credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Linode API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Linode credentials INI file',
            {
                'key': f'API key for Linode account, obtained from {API_KEY_URL} '
                       f'or {API_KEY_URL_V4}'
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_linode_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_linode_client().del_txt_record(domain, validation_name, validation)

    def _get_linode_client(self) -> '_LinodeLexiconClient':
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        api_key = self.credentials.conf('key')
        api_version: Optional[Union[str, int]] = self.credentials.conf('version')
        if api_version == '':
            api_version = None

        if not api_version:
            api_version = 3

            # Match for v4 api key
            regex_v4 = re.compile('^[0-9a-f]{64}$')
            regex_match = regex_v4.match(api_key)
            if regex_match:
                api_version = 4
        else:
            api_version = int(api_version)

        return _LinodeLexiconClient(api_key, api_version)


class _LinodeLexiconClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the Linode API.
    """

    def __init__(self, api_key: str, api_version: int) -> None:
        super().__init__()

        self.api_version = api_version

        if api_version == 3:
            config = dns_common_lexicon.build_lexicon_config('linode', {}, {
                'auth_token': api_key,
            })

            self.provider = linode.Provider(config)
        elif api_version == 4:
            config = dns_common_lexicon.build_lexicon_config('linode4', {}, {
                'auth_token': api_key,
            })

            self.provider = linode4.Provider(config)
        else:
            raise errors.PluginError(
                f'Invalid api version specified: {api_version}. (Supported: 3, 4)'
            )

    def _handle_general_error(self, e: Exception, domain_name: str) -> Optional[errors.PluginError]:
        if not str(e).startswith('Domain not found'):
            return errors.PluginError('Unexpected error determining zone identifier '
                                      f'for {domain_name}: {e}')
        return None
