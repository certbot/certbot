"""DNS Authenticator for DigitalOcean."""
import logging

import zope.interface

from time import sleep

from acme import challenges

from certbot import errors
from certbot import interfaces

from certbot.display import ops
from certbot.display import util as display_util

from certbot.plugins import common

import digitalocean

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """DNS  Authenticator for DigitalOcean

    This Authenticator uses the DigitalOcean API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using DigitalOcean for DNS).'

    _attempt_cleanup = False

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        self.token = None

    @classmethod
    def add_parser_arguments(cls, add):
        add('propagation-seconds',
            default=10,
            type=int,
            help='The number of seconds to wait for DNS to propagate before asking the ACME server '
                 'to verify the DNS record.')
        add('token',
            help='DigitalOcean API Token.')

    def prepare(self): # pylint: disable=missing-docstring
        pass

    def more_info(self): # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the DigitalOcean API.'

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

        self._get_digitalocean_client().add_txt_record(domain, record_name, record_content)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self._attempt_cleanup:
            for achall in achalls:
                self._cleanup_achall(achall)

    def _cleanup_achall(self, achall):
        """foo.bar.baz.
        Deletes the DNS TXT record which would have been created by `_perform_achall`.

        Fails gracefully if no such record exists.

        :param `~certbot.achallenges.AnnotatedChallenge` achall: the challenge to clean up after
        """

        domain = achall.domain
        record_name = achall.validation_domain_name(domain)
        record_content = achall.validation(achall.account_key)

        self._get_digitalocean_client().del_txt_record(domain, record_name, record_content)

    def _setup_credentials(self):
        """
        Establish credentials, prompting if necessary.
        """

        configured_token = self.conf('token')
        if configured_token:
            self.token = configured_token
        else:
            self.token = self._prompt_for_data('API token')

        if self.token:
            setattr(self.config.namespace, self.dest('token'), self.token)
        else:
            raise errors.PluginError('DigitalOcean API token required to proceed.')

    @staticmethod
    def _prompt_for_data(label):
        """
        Prompt the user for a piece of information.

        :param string label: The user-friendly label for this piece of information.
        :returns: The user's response (guaranteed non-empty).
        :rtype: string
        """

        def __validator(i):
            if not i:
                raise errors.PluginError('Please enter an {0}.'.format(label))

        code, response = ops.validated_input(
            __validator,
            'Input DigitalOcean {0}'.format(label),
            force_interactive=True)

        if code == display_util.OK:
            return response
        else:
            return None

    def _get_digitalocean_client(self):
        """
        Helper method to construct a `_DigitalOceanClient`.

        Uses configured credentials.

        :return: a new
        :rtype: `_DigitalOceanClient`
        """

        return _DigitalOceanClient(self.token)


class _DigitalOceanClient(object):
    """
    Encapsulates all communication with the DigitalOcean API.
    """

    def __init__(self, token):
        self.manager = digitalocean.Manager(token=token)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param string domain_name: The domain to use to associate the record with.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the DigitalOcean API
        """

        try:
            domain = self._find_domain(domain_name)
        except digitalocean.Error as e:
            logger.error('Error finding domain using the DigitalOcean API: %s', e)
            raise errors.PluginError('Error finding domain using the DigitalOcean API: {0}'
                                     .format(e))

        try:
            result = domain.create_new_domain_record(
                type='TXT',
                name=self._compute_record_name(domain, record_name),
                data=record_content)

            record_id = result['domain_record']['id']

            logger.debug('Successfully added TXT record with id: %d', record_id)
        except digitalocean.Error as e:
            logger.error('Error adding TXT record using the DigitalOcean API: %s', e)
            raise errors.PluginError('Error adding TXT record using the DigitalOcean API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param string domain_name: The domain to use to associate the record with.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        """

        try:
            domain = self._find_domain(domain_name)
        except digitalocean.Error as e:
            logger.error('Error finding domain using the DigitalOcean API: %s', e)
            return

        matching_records = []
        try:
            domain_records = domain.get_records()

            matching_records = [record for record in domain_records
                                if record.type == 'TXT'
                                and record.name == self._compute_record_name(domain, record_name)
                                and record.data == record_content]
        except digitalocean.Error as e:
            logger.error('Error getting DNS records using the DigitalOcean API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id: %s', record.id)
                record.destroy()
            except digitalocean.Error as e:
                logger.error('Error deleting TXT record %s using the DigitalOcean API: %s',
                             record.id, e)

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param string domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `digitalocean.Domain`
        :raises: errors.PluginError if no matching Domain is found.
        """

        domain_name_guesses = self._domain_name_guesses(domain_name)

        domains = self.manager.get_all_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain.name == guess]

            if len(matches) > 0:
                domain = matches[0]
                logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(domain_name, domain_name_guesses))

    @staticmethod
    def _domain_name_guesses(domain):
        """Return a list of progressively less-specific domain names.

        One of these will probably be the DigitalOcean base domain name.

        :Example:

        >>> _domain_name_guesses('foo.bar.baz.example.com')
        ['foo.bar.baz.example.com', 'bar.baz.example.com', 'baz.example.com', 'example.com', 'com']

        :param string domain: The domain for which to return guesses.
        :returns: The a list of less specific domain names.
        :rtype: list
        """

        fragments = domain.split('.')
        return ['.'.join(fragments[i:]) for i in range(0, len(fragments))]

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from DigitalOcean's point of view, is automatically appended.
        return full_record_name.split("." + domain.name)[0]
