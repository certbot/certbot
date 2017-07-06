"""Common code for DNS Authenticator Plugins."""

import abc
import logging
import os
import stat
from time import sleep

import configobj
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

    def __init__(self, config, name):
        super(DNSAuthenticator, self).__init__(config, name)

        self._attempt_cleanup = False

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
        logger.info("Waiting %d seconds for DNS changes to propagate",
                    self.conf('propagation-seconds'))
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

        :param str domain: The domain being validated.
        :param str validation_domain_name: The validation record domain name.
        :param str validation: The validation record content.
        :raises errors.PluginError: If the challenge cannot be performed
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def _cleanup(self, domain, validation_domain_name, validation):  # pragma: no cover
        """
        Deletes the DNS TXT record which would have been created by `_perform_achall`.

        Fails gracefully if no such record exists.

        :param str domain: The domain being validated.
        :param str validation_domain_name: The validation record domain name.
        :param str validation: The validation record content.
        """
        raise NotImplementedError()

    def _configure(self, key, label):
        """
        Ensure that a configuration value is available.

        If necessary, prompts the user and stores the result.

        :param str key: The configuration key.
        :param str label: The user-friendly label for this piece of information.
        """

        configured_value = self.conf(key)
        if not configured_value:
            new_value = self._prompt_for_data(label)

            setattr(self.config, self.dest(key), new_value)

    def _configure_file(self, key, label, validator=None):
        """
        Ensure that a configuration value is available for a path.

        If necessary, prompts the user and stores the result.

        :param str key: The configuration key.
        :param str label: The user-friendly label for this piece of information.
        """

        configured_value = self.conf(key)
        if not configured_value:
            new_value = self._prompt_for_file(label, validator)

            setattr(self.config, self.dest(key), os.path.abspath(os.path.expanduser(new_value)))

    def _configure_credentials(self, key, label, required_variables=None, validator=None):
        """
        As `_configure_file`, but for a credential configuration file.

        If necessary, prompts the user and stores the result.

        Always stores absolute paths to avoid issues during renewal.

        :param str key: The configuration key.
        :param str label: The user-friendly label for this piece of information.
        :param dict required_variables: Map of variable which must be present to error to display.
        :param callable validator: A method which will be called to validate the
            `CredentialsConfiguration` resulting from the supplied input after it has been validated
            to contain the `required_variables`. Should throw a `~certbot.errors.PluginError` to
            indicate any issue.
        """

        def __validator(filename):
            configuration = CredentialsConfiguration(filename, self.dest)

            if required_variables:
                configuration.require(required_variables)

            if validator:
                validator(configuration)

        self._configure_file(key, label, __validator)

        credentials_configuration = CredentialsConfiguration(self.conf(key), self.dest)
        if required_variables:
            credentials_configuration.require(required_variables)

        if validator:
            validator(credentials_configuration)

        return credentials_configuration

    @staticmethod
    def _prompt_for_data(label):
        """
        Prompt the user for a piece of information.

        :param str label: The user-friendly label for this piece of information.
        :returns: The user's response (guaranteed non-empty).
        :rtype: str
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
            raise errors.PluginError('{0} required to proceed.'.format(label))

    @staticmethod
    def _prompt_for_file(label, validator=None):
        """
        Prompt the user for a path.

        :param str label: The user-friendly label for the file.
        :param callable validator: A method which will be called to validate the supplied input
            after it has been validated to be a non-empty path to an existing file. Should throw a
            `~certbot.errors.PluginError` to indicate any issue.
        :returns: The user's response (guaranteed to exist).
        :rtype: str
        """

        def __validator(filename):
            if not filename:
                raise errors.PluginError('Please enter a valid path to your {0}.'.format(label))

            filename = os.path.expanduser(filename)

            validate_file(filename)

            if validator:
                validator(filename)

        code, response = ops.validated_directory(
            __validator,
            'Input the path to your {0}'.format(label),
            force_interactive=True)

        if code == display_util.OK:
            return response
        else:
            raise errors.PluginError('{0} required to proceed.'.format(label))


class CredentialsConfiguration(object):
    """Represents a user-supplied filed which stores API credentials."""

    def __init__(self, filename, mapper=lambda x: x):
        """
        :param str filename: A path to the configuration file.
        :param callable mapper: A transformation to apply to configuration key names
        :raises errors.PluginError: If the file does not exist or is not a valid format.
        """
        validate_file_permissions(filename)

        try:
            self.confobj = configobj.ConfigObj(filename)
        except configobj.ConfigObjError as e:
            logger.debug("Error parsing credentials configuration: %s", e, exc_info=True)
            raise errors.PluginError("Error parsing credentials configuration: {0}".format(e))

        self.mapper = mapper

    def require(self, required_variables):
        """Ensures that the supplied set of variables are all present in the file.

        :param dict required_variables: Map of variable which must be present to error to display.
        :raises errors.PluginError: If one or more are missing.
        """
        messages = []

        for var in required_variables:
            if not self._has(var):
                messages.append('Property "{0}" not found (should be {1}).'
                                .format(self.mapper(var), required_variables[var]))
            elif not self._get(var):
                messages.append('Property "{0}" not set (should be {1}).'
                                .format(self.mapper(var), required_variables[var]))

        if messages:
            raise errors.PluginError(
                'Missing {0} in credentials configuration file {1}:\n * {2}'.format(
                        'property' if len(messages) == 1 else 'properties',
                        self.confobj.filename,
                        '\n * '.join(messages)
                    )
            )

    def conf(self, var):
        """Find a configuration value for variable `var`, as transformed by `mapper`.

        :param str var: The variable to get.
        :returns: The value of the variable.
        :rtype: str
        """

        return self._get(var)

    def _has(self, var):
        return self.mapper(var) in self.confobj

    def _get(self, var):
        return self.confobj.get(self.mapper(var))


def validate_file(filename):
    """Ensure that the specified file exists."""

    if not os.path.exists(filename):
        raise errors.PluginError('File not found: {0}'.format(filename))

    if not os.path.isfile(filename):
        raise errors.PluginError('Path is not a file: {0}'.format(filename))


def validate_file_permissions(filename):
    """Ensure that the specified file exists and warn about unsafe permissions."""

    validate_file(filename)

    permissions = stat.S_IMODE(os.stat(filename).st_mode)
    if permissions & stat.S_IRWXO:
        logger.warning('Unsafe permissions on credentials configuration file: %s', filename)


def base_domain_name_guesses(domain):
    """Return a list of progressively less-specific domain names.

    One of these will probably be the domain name known to the DNS provider.

    :Example:

    >>> base_domain_name_guesses('foo.bar.baz.example.com')
    ['foo.bar.baz.example.com', 'bar.baz.example.com', 'baz.example.com', 'example.com', 'com']

    :param str domain: The domain for which to return guesses.
    :returns: The a list of less specific domain names.
    :rtype: list
    """

    fragments = domain.split('.')
    return ['.'.join(fragments[i:]) for i in range(0, len(fragments))]
