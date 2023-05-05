"""DNS Authenticator for Cloudflare."""
import logging
import os
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

import CloudFlare

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dash.cloudflare.com/?to=/:account/profile/api-tokens'


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Cloudflare

    This Authenticator uses the Cloudflare API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Cloudflare for '
                   'DNS).')
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Cloudflare credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Cloudflare API.'

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        token = os.getenv("CLOUDFLARE_API_TOKEN", default = credentials.conf('api-token'))
        email = os.getenv("CLOUDFLARE_EMAIL", default = credentials.conf('email'))
        key = os.getenv("CLOUDFLARE_API_KEY", default = credentials.conf('api-key'))
        if token:
            if email or key:
                raise errors.PluginError('{}: dns_cloudflare_email and dns_cloudflare_api_key are '
                                         'not needed when using an API Token'
                                         .format(credentials.confobj.filename))
        elif email or key:
            if not email:
                raise errors.PluginError('{}: dns_cloudflare_email is required when using a Global '
                                         'API Key. (should be email address associated with '
                                         'Cloudflare account)'.format(credentials.confobj.filename))
            if not key:
                raise errors.PluginError('{}: dns_cloudflare_api_key is required when using a '
                                         'Global API Key. (see {})'
                                         .format(credentials.confobj.filename, ACCOUNT_URL))
        else:
            raise errors.PluginError('{}: Either dns_cloudflare_api_token (recommended), or '
                                     'dns_cloudflare_email and dns_cloudflare_api_key are required.'
                                     ' (see {})'.format(credentials.confobj.filename, ACCOUNT_URL))

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Cloudflare credentials INI file',
            None,
            self._validate_credentials
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_cloudflare_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_cloudflare_client().del_txt_record(domain, validation_name, validation)

    def _get_cloudflare_client(self) -> "_CloudflareClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        if self.credentials.conf('api-token'):
            return _CloudflareClient(api_token = self.credentials.conf('api-token'))
        return _CloudflareClient(email = self.credentials.conf('email'),
                                 api_key = self.credentials.conf('api-key'))


class _CloudflareClient:
    """
    Encapsulates all communication with the Cloudflare API.
    """

    def __init__(self, email: Optional[str] = None, api_key: Optional[str] = None,
                 api_token: Optional[str] = None) -> None:
        if email:
            # If an email was specified, we're using an email/key combination and not a token.
            # We can't use named arguments in this case, as it would break compatibility with
            # the Cloudflare library since version 2.10.1, as the `token` argument was used for
            # tokens and keys alike and the `key` argument did not exist in earlier versions.
            self.cf = CloudFlare.CloudFlare(email, api_key)
        else:
            # If no email was specified, we're using just a token. Let's use the named argument
            # for simplicity, which is compatible with all (current) versions of the Cloudflare
            # library.
            self.cf = CloudFlare.CloudFlare(token=api_token)

    def add_txt_record(self, domain: str, record_name: str, record_content: str,
                       record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Cloudflare zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Cloudflare API
        """

        zone_id = self._find_zone_id(domain)

        data = {'type': 'TXT',
                'name': record_name,
                'content': record_content,
                'ttl': record_ttl}

        try:
            logger.debug('Attempting to add record to zone %s: %s', zone_id, data)
            self.cf.zones.dns_records.post(zone_id, data=data)  # zones | pylint: disable=no-member
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            code = int(e)
            hint = None

            if code == 1009:
                hint = 'Does your API token have "Zone:DNS:Edit" permissions?'

            logger.error('Encountered CloudFlareAPIError adding TXT record: %d %s', e, e)
            raise errors.PluginError('Error communicating with the Cloudflare API: {0}{1}'
                                     .format(e, ' ({0})'.format(hint) if hint else ''))

        record_id = self._find_txt_record_id(zone_id, record_name, record_content)
        logger.debug('Successfully added TXT record with record_id: %s', record_id)

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Cloudflare zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            zone_id = self._find_zone_id(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding zone_id during deletion: %s', e)
            return

        if zone_id:
            record_id = self._find_txt_record_id(zone_id, record_name, record_content)
            if record_id:
                try:
                    # zones | pylint: disable=no-member
                    self.cf.zones.dns_records.delete(zone_id, record_id)
                    logger.debug('Successfully deleted TXT record.')
                except CloudFlare.exceptions.CloudFlareAPIError as e:
                    logger.warning('Encountered CloudFlareAPIError deleting TXT record: %s', e)
            else:
                logger.debug('TXT record not found; no cleanup needed.')
        else:
            logger.debug('Zone not found; no cleanup needed.')

    def _find_zone_id(self, domain: str) -> str:
        """
        Find the zone_id for a given domain.

        :param str domain: The domain for which to find the zone_id.
        :returns: The zone_id, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no zone_id is found.
        """

        zone_name_guesses = dns_common.base_domain_name_guesses(domain)
        zones: List[Dict[str, Any]] = []
        code = msg = None

        for zone_name in zone_name_guesses:
            params = {'name': zone_name,
                      'per_page': 1}

            try:
                zones = self.cf.zones.get(params=params)  # zones | pylint: disable=no-member
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                code = int(e)
                msg = str(e)
                hint = None

                if code == 6003:
                    hint = ('Did you copy your entire API token/key? To use Cloudflare tokens, '
                            'you\'ll need the python package cloudflare>=2.3.1.{}'
                    .format(' This certbot is running cloudflare ' + str(CloudFlare.__version__)
                    if hasattr(CloudFlare, '__version__') else ''))
                elif code == 9103:
                    hint = 'Did you enter the correct email address and Global key?'
                elif code == 9109:
                    hint = 'Did you enter a valid Cloudflare Token?'

                if hint:
                    raise errors.PluginError('Error determining zone_id: {0} {1}. Please confirm '
                                  'that you have supplied valid Cloudflare API credentials. ({2})'
                                                                         .format(code, msg, hint))
                else:
                    logger.debug('Unrecognised CloudFlareAPIError while finding zone_id: %d %s. '
                                 'Continuing with next zone guess...', e, e)

            if zones:
                zone_id = zones[0]['id']
                logger.debug('Found zone_id of %s for %s using name %s', zone_id, domain, zone_name)
                return zone_id

        if msg is not None:
            if 'com.cloudflare.api.account.zone.list' in msg:
                raise errors.PluginError('Unable to determine zone_id for {0} using zone names: '
                                         '{1}. Please confirm that the domain name has been '
                                         'entered correctly and your Cloudflare Token has access '
                                         'to the domain.'.format(domain, zone_name_guesses))
            else:
                raise errors.PluginError('Unable to determine zone_id for {0} using zone names: '
                                         '{1}. The error from Cloudflare was: {2} {3}.'
                                         .format(domain, zone_name_guesses, code, msg))
        else:
            raise errors.PluginError('Unable to determine zone_id for {0} using zone names: '
                                     '{1}. Please confirm that the domain name has been '
                                     'entered correctly and is already associated with the '
                                     'supplied Cloudflare account.'
                                     .format(domain, zone_name_guesses))

    def _find_txt_record_id(self, zone_id: str, record_name: str,
                            record_content: str) -> Optional[str]:
        """
        Find the record_id for a TXT record with the given name and content.

        :param str zone_id: The zone_id which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """

        params = {'type': 'TXT',
                  'name': record_name,
                  'content': record_content,
                  'per_page': 1}
        try:
            # zones | pylint: disable=no-member
            records = self.cf.zones.dns_records.get(zone_id, params=params)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            logger.debug('Encountered CloudFlareAPIError getting TXT record_id: %s', e)
            records = []

        if records:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.
            return records[0]['id']
        logger.debug('Unable to find TXT record.')
        return None
