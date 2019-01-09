"""DNS Authenticator for OVH DNS."""
import logging

import zope.interface
from lexicon.providers import ovh

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://eu.api.ovh.com/createToken/ or https://ca.api.ovh.com/createToken/'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for OVH

    This Authenticator uses the OVH API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using OVH for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='OVH credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the OVH API.'

    def _setup_credentials(self):
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

    def _perform(self, domain, validation_name, validation):
        self._get_ovh_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_ovh_client().del_txt_record(domain, validation_name, validation)

    def _get_ovh_client(self):
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

    def __init__(self, endpoint, application_key, application_secret, consumer_key, ttl):
        super(_OVHLexiconClient, self).__init__()

        config = dns_common_lexicon.build_lexicon_config('ovh', {
            'ttl': ttl,
        }, {
            'auth_entrypoint': endpoint,
            'auth_application_key': application_key,
            'auth_application_secret': application_secret,
            'auth_consumer_key': consumer_key,
        })

        self.provider = ovh.Provider(config)

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Is your Application Secret value correct?'
        if str(e).startswith('403 Client Error:'):
            hint = 'Are your Application Key and Consumer Key values correct?'

        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        if domain_name in str(e) and str(e).endswith('not found'):
            return

        super(_OVHLexiconClient, self)._handle_general_error(e, domain_name)
