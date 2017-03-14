"""DNS Authenticator for Cloudflare."""
import logging

import zope.interface

from time import sleep

from acme import challenges

from certbot import errors
from certbot import interfaces

from certbot.display import util as display_util

from certbot.plugins import common

import CloudFlare

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """DNS  Authenticator for Cloudflare

    This Authenticator uses the Cloudflare API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Cloudflare for DNS).'

    _attempt_cleanup = False

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        self.email = None
        self.api_key = None

    @classmethod
    def add_parser_arguments(cls, add):
        add('propagation-seconds',
            default=10,
            type=int,
            help='The number of seconds to wait for DNS to propagate before asking the ACME server '
                 'to verify the DNS record.')
        add('email',
            help='Email address associated with Cloudflare account.')
        add('api-key',
            help='API key for Cloudflare account. ' +
                 '(Which can be obtained from https://www.cloudflare.com/a/account/my-account)')

    def prepare(self): # pylint: disable=missing-docstring
        pass

    def more_info(self): # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Cloudflare API.'

    def get_chall_pref(self, unused_domain): # pylint: disable=missing-docstring,no-self-use
        return [challenges.DNS01]

    def perform(self, achalls): # pylint: disable=missing-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        responses = []
        for achall in achalls:
            self._perform_achall(achall)
            responses.append(achall.response(achall.account_key))

        # DNS updates take time to propagate and checking to see if the update has occurred is not
        # reliable (the machine this code is running on might be able to see an update before
        # the ACME server). So: we sleep for a short amount of time we believe to be long enough.
        sleep(self.conf('propagation-seconds'))

        return responses

    def _perform_achall(self, achall):
        """
        Performs a dns-01 challenge by creating a DNS TXT record.

        :param `~certbot.achallenges.AnnotatedChallenge` achall: the challenge to perform
        :raises errors.PluginError: If the challenge cannot be performed
        """

        domain = achall.domain
        record_name = achall.validation_domain_name(domain)
        record_content = achall.validation(achall.account_key)
        ttl = 120

        self._get_cloudflare_client().add_txt_record(domain, record_name, record_content, ttl)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self._attempt_cleanup:
            for achall in achalls:
                self._cleanup_achall(achall)

    def _cleanup_achall(self, achall):
        """
        Deletes the DNS TXT record which would have been created by `_perform_achall`.

        Fails gracefully if no such record exists.

        :param `~certbot.achallenge s.AnnotatedChallenge` achall: the challenge to clean up after
        """

        domain = achall.domain
        record_name = achall.validation_domain_name(domain)
        record_content = achall.validation(achall.account_key)

        self._get_cloudflare_client().del_txt_record(domain, record_name, record_content)

    def _setup_credentials(self):
        """
        Establish credentials, prompting if necessary.
        """

        # XXX: We could make these optional and let CloudFlare.CloudFlare attempt to read them from
        #      .cloudflare.cfg or ~/.cloudflare.cfg or ~/.cloudflare/cloudflare.cfg
        #
        #      Marking them as required seems to provide for a better user experience.

        configured_email = self.conf('email')
        if configured_email:
            self.email = configured_email
        else:
            self.email = self._prompt_for_data('email address')

        if self.email:
            setattr(self.config, self.dest('email'), self.email)
        else:
            raise errors.PluginError('Cloudflare account email address required to proceed.')

        configured_api_key = self.conf('api-key')
        if configured_api_key:
            self.api_key = configured_api_key
        else:
            self.api_key = self._prompt_for_data('API key')

        if self.api_key:
            setattr(self.config, self.dest('api-key'), self.api_key)
        else:
            raise errors.PluginError('Cloudflare account API key required to proceed.')

    @staticmethod
    def _prompt_for_data(label):
        """
        Prompt the user for a piece of information.

        :param string label: The user-friendly label for this piece of information.
        :returns: The user's response (guaranteed non-empty).
        :rtype: string
        """

        display = zope.component.getUtility(interfaces.IDisplay)

        while True:
            code, response = display.input(
                'Input Cloudflare account {0}'.format(label),
                force_interactive=True)
            if code == display_util.HELP:
                # Displaying help is not currently implemented
                return None
            elif code == display_util.CANCEL:
                return None
            else:  # code == display_util.OK
                if not response:
                    display.notification('Please enter an {0}.'.format(label), pause=False)
                else:
                    return response

    def _get_cloudflare_client(self):
        """
        Helper method to construct a `_CloudflareClient`.

        Uses configured credentials.

        :return: a new
        :rtype: `_CloudflareClient`
        """

        return _CloudflareClient(self.email, self.api_key)


class _CloudflareClient(object):
    """
    Encapsulates all communication with the Cloudflare API.
    """

    def __init__(self, email, api_key):
        self.cf = CloudFlare.CloudFlare(email, api_key)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param string domain: The domain to use to look up the Cloudflare zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises: errors.PluginError if an error occurs communicating with the Cloudflare API
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
            logger.error('Encountered CloudFlareAPIError adding TXT record: %d %s', e, e)
            raise errors.PluginError('Error communicating with the Cloudflare API: {0}'.format(e))

        record_id = self._find_txt_record_id(zone_id, record_name, record_content)
        logger.debug('Successfully added TXT record with record_id: %s', record_id)

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param string domain: The domain to use to look up the Cloudflare zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
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
                    logger.warn('Encountered CloudFlareAPIError deleting TXT record: %s', e)
            else:
                logger.debug('TXT record not found; no cleanup needed.')
        else:
            logger.debug('Zone not found; no cleanup needed.')

    def _find_zone_id(self, domain):
        """
        Find the zone_id for a given domain.

        :param string domain: The domain for which to find the zone_id.
        :returns: The zone_id, if found.
        :rtype: string
        :raises: errors.PluginError if no zone_id is found.
        """

        zone_name_guesses = self._zone_name_guesses(domain)

        for zone_name in zone_name_guesses:
            params = {'name': zone_name,
                      'per_page': 1}

            try:
                zones = self.cf.zones.get(params=params)  # zones | pylint: disable=no-member
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                code = int(e)
                hint = None

                if code == 6003:
                    hint = 'Did you copy your entire API key?'
                elif code == 9103:
                    hint = 'Did you enter the correct email address?'

                raise errors.PluginError('Error determining zone_id: {0} {1}. Please confirm that '
                                         'you have supplied valid Cloudflare API credentials.{2}'
                                         .format(code, e, ' ({0})'.format(hint) if hint else ''))

            if len(zones) > 0:
                zone_id = zones[0]['id']
                logger.debug('Found zone_id of %s for %s using name %s', zone_id, domain, zone_name)
                return zone_id

        raise errors.PluginError('Unable to determine zone_id for {0} using zone names: {1}. '
                                 'Please confirm that the domain name has been entered correctly '
                                 'and is already associated with the supplied Cloudflare account.'
                                 .format(domain, zone_name_guesses))

    def _find_txt_record_id(self, zone_id, record_name, record_content):
        """
        Find the record_id for a TXT record with the given name and content.

        :param string zone_id: The zone_id which contains the record.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: string
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

        if len(records) > 0:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.
            return records[0]['id']
        else:
            logger.debug('Unable to find TXT record.')

    @staticmethod
    def _zone_name_guesses(domain):
        """Return a list of progressively less-specific domain names.

        One of these will probably be the Cloudflare zone name.

        :Example:

        >>> _zone_name_guesses('foo.bar.baz.example.com')
        ['foo.bar.baz.example.com', 'bar.baz.example.com', 'baz.example.com', 'example.com', 'com']

        :param string domain: The domain for which to return guesses.
        :returns: The a list of less specific domain names.
        :rtype: list
        """

        fragments = domain.split('.')
        return ['.'.join(fragments[i:]) for i in range(0, len(fragments))]
