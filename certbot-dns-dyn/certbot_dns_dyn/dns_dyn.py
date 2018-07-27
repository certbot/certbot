"""DNS Authenticator for DYN."""
import logging
from time import sleep

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

from dyn.tm.session import DynectSession
from dyn.tm.zones import get_all_zones
from dyn.tm.errors import DynectAuthError
from dyn.tm.errors import DynectCreateError
from dyn.tm.errors import DynectDeleteError

logger = logging.getLogger(__name__)

CREDENTIALS_URL = 'https://manage.dynect.net/users/mysettings/'

def rrem(val, rem):
    """Helper method for removing string trailing content"""
    if val.endswith(rem):
        return val[:-len(rem)]
    else:
        return val

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for DYN

    This Authenticator uses the DYN API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using DYN for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self._client = None
        self._zone_cache = None
        self._attempt_cleanup = False

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='DYN credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DYN API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'DYN credentials INI file',
            {
                'customer': 'Customer name, obtained from {0}'.format(CREDENTIALS_URL),
                'username': 'Username, obtained from {0}'.format(CREDENTIALS_URL),
                'password': 'Password, obtained from {0}'.format(CREDENTIALS_URL),
            }
        )

    def _get_dyn_client(self):
        return DynectSession(self.credentials.conf('customer'),
                             self.credentials.conf('username'),
                             self.credentials.conf('password'))

    def _find_zone(self, domain):
        domain_name_guesses = dns_common.base_domain_name_guesses(domain)
        dyn_domains = get_all_zones()

        for domain in domain_name_guesses:
            found_zone = [dyn_domain for dyn_domain in dyn_domains if
                            rrem(dyn_domain.fqdn, '.') == domain]
            if len(found_zone) > 0:
                return found_zone[0]

        return None

    def _perform(self, domain, validation_domain_name, validation): # pragma: no cover
        pass

    def _cleanup(self, domain, validation_domain_name, validation): # pragma: no cover
        pass

    def perform(self, achalls):
        self._setup_credentials()
        self._client = self._get_dyn_client()

        try:
            self._client.authenticate()
        except DynectAuthError:
            raise errors.PluginError("Invalid credentials for DYN")

        self._zone_cache = {}

        responses = []
        for achall in achalls:
            zone = self._find_zone(achall.domain)
            if zone:
                zone_fqdn = rrem(zone.fqdn, '.')
                self._zone_cache[achall.domain] = zone

                record_name = achall.validation_domain_name(achall.domain)
                try:
                    zone.add_record(rrem(rrem(record_name, zone_fqdn), '.'),
                                    record_type='TXT',
                                    txtdata=achall.validation(achall.account_key))
                except DynectCreateError:
                    raise errors.PluginError("Unable to create record: {0}".format(
                        record_name))
            else:
                raise errors.PluginError("Zone not found for domain: {0}".format(
                    achall.domain))

            responses.append(achall.response(achall.account_key))

        for _, zone in self._zone_cache.items():
            zone.publish("Let's Encrypt validation token added by Certbot")
            self._attempt_cleanup = True

        sleep(self.conf('propagation-seconds'))
        return responses

    def cleanup(self, achalls):
        if self._attempt_cleanup:
            for achall in achalls:
                zone = self._zone_cache[achall.domain]
                if zone:
                    zone_fqdn = rrem(zone.fqdn, '.')
                    record_name = achall.validation_domain_name(achall.domain)

                    dyn_node = zone.get_node(rrem(rrem(record_name, zone_fqdn), '.'))
                    dyn_records = dyn_node.get_all_records_by_type('TXT')
                    for dyn_record in dyn_records:
                        if rrem(dyn_record.fqdn, '.') == record_name:
                            try:
                                dyn_record.delete()
                            except DynectDeleteError:
                                logger.error("Unable to delete record: %s",
                                    record_name)
                            break

                    zone.publish("Let's Encrypt validation token removed by Certbot")
            self._client.log_out()

