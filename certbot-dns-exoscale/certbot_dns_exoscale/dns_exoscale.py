"""DNS Authenticator for Exoscale DNS."""
import logging

import zope.interface
from lexicon.providers import exoscale

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

ACCOUNT_URL = "https://portal.exoscale.com/account/profile/api"


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Exoscale

    This Authenticator uses the Exoscale DNS API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using Exoscale for DNS)."
    )
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=30
        )
        add("credentials", help="Exoscale credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to "
            "a dns-01 challenge using the Exoscale API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Exoscale credentials INI file",
            {
                "key": "API Key for Exoscale API. (See {0}.)".format(
                    ACCOUNT_URL
                ),
                "secret": "API Secret for Exoscale API. (See {0}.)".format(
                    ACCOUNT_URL
                ),
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_exoscale_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_exoscale_client().del_txt_record(
            domain, validation_name, validation
        )

    def _get_exoscale_client(self):
        return _ExoscaleLexiconClient(
            self.credentials.conf("key"),
            self.credentials.conf("secret"),
            self.ttl,
        )


class _ExoscaleLexiconClient(dns_common_lexicon.LexiconClient):
    """Encapsulate all communication with the Exoscale via Lexicon"""

    def __init__(self, key, secret, ttl):
        super(_ExoscaleLexiconClient, self).__init__()

        self.provider = exoscale.Provider(
            {"auth_key": key, "auth_secret": secret, "ttl": ttl}
        )
