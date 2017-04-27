"""Common code for DNS Authenticator Plugins."""

import abc
import logging
from requests.exceptions import HTTPError, RequestException
from time import sleep

import zope.interface

from acme import challenges

from certbot import errors
from certbot import interfaces

from certbot.display import ops
from certbot.display import util as display_util

from certbot.plugins import common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class DNSAuthenticator(common.Plugin):
    """Base class for DNS  Authenticators"""

    _attempt_cleanup = False

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=10):  # pylint: disable=arguments-differ
        add('propagation-seconds',
            default=default_propagation_seconds,
            type=int,
            help='The number of seconds to wait for DNS to propagate before asking the ACME server '
                 'to verify the DNS record.')

    def get_chall_pref(self, unused_domain): # pylint: disable=missing-docstring,no-self-use
        return [challenges.DNS01]

    def prepare(self): # pylint: disable=missing-docstring
        pass

    def perform(self, achalls): # pylint: disable=missing-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        responses = []
        for achall in achalls:
            domain = achall.domain
            validation_domain_name = achall.validation_domain_name(domain)
            validation = achall.validation(achall.account_key)

            self._perform(domain, validation_domain_name, validation)
            responses.append(achall.response(achall.account_key))

        # DNS updates take time to propagate and checking to see if the update has occurred is not
        # reliable (the machine this code is running on might be able to see an update before
        # the ACME server). So: we sleep for a short amount of time we believe to be long enough.
        sleep(self.conf('propagation-seconds'))

        return responses

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self._attempt_cleanup:
            for achall in achalls:
                domain = achall.domain
                validation_domain_name = achall.validation_domain_name(domain)
                validation = achall.validation(achall.account_key)

                self._cleanup(domain, validation_domain_name, validation)

    @abc.abstractmethod
    def _setup_credentials(self):  # pragma: no cover
        """
        Establish credentials, prompting if necessary.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def _perform(self, domain, validation_domain_name, validation):  # pragma: no cover
        """
        Performs a dns-01 challenge by creating a DNS TXT record.

        :param string domain: The domain being validated.
        :param string validation_domain_name: The validation record domain name.
        :param string validation: The validation record content.
        :raises errors.PluginError: If the challenge cannot be performed
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def _cleanup(self, domain, validation_domain_name, validation):  # pragma: no cover
        """
        Deletes the DNS TXT record which would have been created by `_perform_achall`.

        Fails gracefully if no such record exists.

        :param string domain: The domain being validated.
        :param string validation_domain_name: The validation record domain name.
        :param string validation: The validation record content.
        """
        raise NotImplementedError()

    def _configure(self, key, label):
        """
        Ensure that a configuration value is available.

        If necessary, prompts the user and stores the result.

        :param string key: The configuration key.
        :param string label: The user-friendly label for this piece of information.
        """

        configured_value = self.conf(key)
        if not configured_value:
            new_value = self._prompt_for_data(label)

            if new_value:
                setattr(self.config, self.dest(key), new_value)
            else:
                raise errors.PluginError('{0} required to proceed.'.format(label))

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
                raise errors.PluginError('Please enter your {0}.'.format(label))

        code, response = ops.validated_input(
            __validator,
            'Input your {0}'.format(label),
            force_interactive=True)

        if code == display_util.OK:
            return response
        else:
            return None


class LexiconClient(object):
    """
    Encapsulates all communication with a DNS provider via Lexicon.
    """

    provider = None

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param string domain: The domain to use to look up the managed zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the DNS Provider API
        """
        self._find_domain_id(domain)

        try:
            self.provider.create_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param string domain: The domain to use to look up the managed zone.
        :param string record_name: The record name (typically beginning with '_acme-challenge.').
        :param string record_content: The record content (typically the challenge validation).
        :raises: errors.PluginError if an error occurs communicating with the DNS Provider  API
        """
        try:
            self._find_domain_id(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e,
                         exc_info=True)
            return

        try:
            self.provider.delete_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error deleting TXT record: %s', e, exc_info=True)

    def _find_domain_id(self, domain):
        """
        Find the domain_id for a given domain.

        :param string domain: The domain for which to find the domain_id.
        :raises: errors.PluginError if the domain_id cannot be found.
        """

        domain_name_guesses = base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                self.provider.options['domain'] = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                hint = self.determine_error_hint(e)

                raise errors.PluginError('Error determining domain_id: {0}.{1}'
                                         .format(e, ' ({0})'.format(hint) if hint else ''))
            except Exception as e:  # pylint: disable=broad-except
                if str(e).startswith('No domain found'):
                    pass
                else:
                    raise errors.PluginError('Unexpected error determining zone_id: {0}'.format(e))

        raise errors.PluginError('Unable to determine zone_id for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))

    @abc.abstractmethod
    def determine_error_hint(self, e):  # pragma: no cover
        """
        Examine an error and determine what hint, if any, should be displayed to the user.

        Allows Certbot to provide better error messages than the libraries it uses.

        :param exc e: The exception to examine.
        :return: A hint to return to the user or `None`.
        :rtype string:
        """
        raise NotImplementedError()



def base_domain_name_guesses(domain):
    """Return a list of progressively less-specific domain names.

    One of these will probably be the domain name known to the DNS provider.

    :Example:

    >>> base_domain_name_guesses('foo.bar.baz.example.com')
    ['foo.bar.baz.example.com', 'bar.baz.example.com', 'baz.example.com', 'example.com', 'com']

    :param string domain: The domain for which to return guesses.
    :returns: The a list of less specific domain names.
    :rtype: list
    """

    fragments = domain.split('.')
    return ['.'.join(fragments[i:]) for i in range(0, len(fragments))]
