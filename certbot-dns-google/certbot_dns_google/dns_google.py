"""DNS Authenticator for Google Cloud DNS."""
import json
import logging

import zope.interface
from googleapiclient import discovery
from googleapiclient import errors as googleapiclient_errors
from oauth2client.service_account import ServiceAccountCredentials

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCT_URL = 'https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount'
PERMISSIONS_URL = 'https://cloud.google.com/dns/access-control#permissions_and_roles'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Google Cloud DNS

    This Authenticator uses the Google Cloud DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Google Cloud DNS '
                   'for DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials',
            help=('Path to Google Cloud DNS service account JSON file. (See {0} for' +
                  'information about creating a service account and {1} for information about the' +
                  'required permissions.)').format(ACCT_URL, PERMISSIONS_URL))

    def more_info(self): # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Google Cloud DNS API.'

    def _setup_credentials(self):
        self._configure_file('credentials', 'path to Google Cloud DNS service account JSON file')

        dns_common.validate_file_permissions(self.conf('credentials'))

    def _perform(self, domain, validation_name, validation):
        self._get_google_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_google_client().del_txt_record(domain, validation_name, validation, self.ttl)

    def _get_google_client(self):
        return _GoogleClient(self.conf('credentials'))


class _GoogleClient(object):
    """
    Encapsulates all communication with the Google Cloud DNS API.
    """

    def __init__(self, account_json):

        scopes = ['https://www.googleapis.com/auth/ndev.clouddns.readwrite']
        credentials = ServiceAccountCredentials.from_json_keyfile_name(account_json, scopes)
        self.dns = discovery.build('dns', 'v1', credentials=credentials, cache_discovery=False)
        with open(account_json) as account:
            self.project_id = json.load(account)['project_id']

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Google API
        """

        zone_id = self._find_managed_zone_id(domain)

        data = {
            "kind": "dns#change",
            "additions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": [record_content, ],
                    "ttl": record_ttl,
                },
            ],
        }

        changes = self.dns.changes()  # changes | pylint: disable=no-member

        try:
            request = changes.create(project=self.project_id, managedZone=zone_id, body=data)
            response = request.execute()

            status = response['status']
            change = response['id']
            while status == 'pending':
                request = changes.get(project=self.project_id, managedZone=zone_id, changeId=change)
                response = request.execute()
                status = response['status']
        except googleapiclient_errors.Error as e:
            logger.error('Encountered error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Google Cloud DNS API: {0}'
                                     .format(e))

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Google API
        """

        try:
            zone_id = self._find_managed_zone_id(domain)
        except errors.PluginError as e:
            logger.warn('Error finding zone. Skipping cleanup.')
            return

        data = {
            "kind": "dns#change",
            "deletions": [
                {
                    "kind": "dns#resourceRecordSet",
                    "type": "TXT",
                    "name": record_name + ".",
                    "rrdatas": [record_content, ],
                    "ttl": record_ttl,
                },
            ],
        }

        changes = self.dns.changes()  # changes | pylint: disable=no-member

        try:
            request = changes.create(project=self.project_id, managedZone=zone_id, body=data)
            request.execute()
        except googleapiclient_errors.Error as e:
            logger.warn('Encountered error deleting TXT record: %s', e)

    def _find_managed_zone_id(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """

        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)

        mz = self.dns.managedZones()  # managedZones | pylint: disable=no-member
        for zone_name in zone_dns_name_guesses:
            try:
                request = mz.list(project=self.project_id, dnsName=zone_name + '.')
                response = request.execute()
                zones = response['managedZones']
            except googleapiclient_errors.Error as e:
                raise errors.PluginError('Encountered error finding managed zone: {0}'
                                         .format(e))

            if len(zones) > 0:
                zone_id = zones[0]['id']
                logger.debug('Found id of %s for %s using name %s', zone_id, domain, zone_name)
                return zone_id

        raise errors.PluginError('Unable to determine managed zone for {0} using zone names: {1}.'
                                 .format(domain, zone_dns_name_guesses))
