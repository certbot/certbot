"""Common code for DNS Authenticator Plugins."""

import abc

from time import sleep

import zope.interface

from acme import challenges

from certbot import errors
from certbot import interfaces

from certbot.display import ops
from certbot.display import util as display_util

from certbot.plugins import common


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
