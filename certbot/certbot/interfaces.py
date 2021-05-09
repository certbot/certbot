"""Certbot client interfaces."""
from abc import ABCMeta, abstractmethod, abstractproperty
from argparse import ArgumentParser
from typing import Optional, Iterable, List, Union, Tuple

import zope.interface

# pylint: disable=no-self-argument,no-method-argument,inherit-non-class
from acme.challenges import Challenge, ChallengeResponse
from certbot.achallenges import AnnotatedChallenge


class AccountStorage(metaclass=ABCMeta):
    """Accounts storage interface."""

    @abstractmethod
    def find_all(self):  # pragma: no cover
        """Find all accounts.

        :returns: All found accounts.
        :rtype: list

        """
        raise NotImplementedError()

    @abstractmethod
    def load(self, account_id):  # pragma: no cover
        """Load an account by its id.

        :raises .AccountNotFound: if account could not be found
        :raises .AccountStorageError: if account could not be loaded

        """
        raise NotImplementedError()

    @abstractmethod
    def save(self, account, client):  # pragma: no cover
        """Save account.

        :raises .AccountStorageError: if account could not be saved

        """
        raise NotImplementedError()


class IConfig(zope.interface.Interface):
    pass


@zope.interface.implementer(IConfig)
class Config(metaclass=ABCMeta):
    """Certbot user-supplied configuration.

    .. warning:: The values stored in the configuration have not been
        filtered, stripped or sanitized.

    """

    @property
    @abstractmethod
    def server(self) -> str:
        """ACME Directory Resource URI."""

    @property
    @abstractmethod
    def email(self) -> str:
        """Email used for registration and recovery contact.

        Use comma to register multiple emails,
        ex: u1@example.com,u2@example.com. (default: Ask).
        """

    @property
    @abstractmethod
    def rsa_key_size(self) -> int:
        """Size of the RSA key."""

    @property
    @abstractmethod
    def elliptic_curve(self) -> str:
        """The SECG elliptic curve name to use.

        Please see RFC 8446 for supported values.
        """

    @property
    @abstractmethod
    def key_type(self) -> str:
        """Type of generated private key.

        Only *ONE* per invocation can be provided at this time.
        """

    @property
    @abstractmethod
    def must_staple(self) -> bool:
        """Adds the OCSP Must Staple extension to the certificate.

        Autoconfigures OCSP Stapling for supported setups
        (Apache version >= 2.3.3 ).
        """

    @property
    @abstractmethod
    def config_dir(self) -> str:
        """Configuration directory."""

    @property
    @abstractmethod
    def work_dir(self) -> str:
        """Working directory."""

    @property
    @abstractmethod
    def account_dir(self) -> str:
        """Directory where all account information is stored."""

    @property
    @abstractmethod
    def backup_dir(self) -> str:
        """Configuration backups directory."""

    @property
    @abstractmethod
    def csr_dir(self) -> str:
        """Directory where new Certificate Signing Requests (CSRs) are saved."""

    @property
    @abstractmethod
    def in_progress_dir(self) -> str:
        """Directory used before a permanent checkpoint is finalized."""

    @property
    @abstractmethod
    def key_dir(self) -> str:
        """Keys storage."""

    @property
    @abstractmethod
    def temp_checkpoint_dir(self) -> str:
        """Temporary checkpoint directory."""

    @property
    @abstractmethod
    def no_verify_ssl(self) -> bool:
        """Disable verification of the ACME server's certificate."""

    @property
    @abstractmethod
    def http01_port(self) -> int:
        """Port used in the http-01 challenge.

        This only affects the port Certbot listens on.
        A conforming ACME server will still attempt to connect on port 80.
        """

    @property
    @abstractmethod
    def http01_address(self) -> str:
        """The address the server listens to during http-01 challenge."""

    @property
    @abstractmethod
    def https_port(self) -> int:
        """Port used to serve HTTPS.

        This affects which port Nginx will listen on after a LE certificate
        is installed.
        """

    @property
    @abstractmethod
    def pref_challs(self) -> List[str]:
        """List of user specified preferred challenges.

        Sorted with the most preferred challenge listed first.
        """

    @property
    @abstractmethod
    def allow_subset_of_names(self) -> bool:
        """Allow only a subset of names to be authorized to perform validations.

        When performing domain validation, do not consider it a failure
        if authorizations can not be obtained for a strict subset of
        the requested domains. This may be useful for allowing renewals for
        multiple domains to succeed even if some domains no longer point
        at this system.
        """

    @property
    @abstractmethod
    def strict_permissions(self) -> bool:
        """Enable strict permissions checks.

        Require that all configuration files are owned by the current
        user; only needed if your config is somewhere unsafe like /tmp/.
        """

    @property
    @abstractmethod
    def disable_renew_updates(self) -> bool:
        """Disable renewal updates.

        If updates provided by installer enhancements when Certbot is being run
        with \"renew\" verb should be disabled.
        """

    @property
    @abstractmethod
    def preferred_chain(self) -> str:
        """Set the preferred certificate chain to issue a certificate.

        If the CA offers multiple certificate chains, prefer the chain whose
        topmost certificate was issued from this Subject Common Name.
        If no match, the default offered chain will be used.
        """


class IPluginFactory(zope.interface.Interface):
    pass


class IPlugin(zope.interface.Interface):
    pass


@zope.interface.provider(IPluginFactory)
@zope.interface.implementer(IPlugin)
class Plugin(metaclass=ABCMeta):
    """Certbot plugin.

    Objects providing this interface will be called without satisfying
    any entry point "extras" (extra dependencies) you might have defined
    for your plugin, e.g (excerpt from ``setup.py`` script)::

      setup(
          ...
          entry_points={
              'certbot.plugins': [
                  'name=example_project.plugin[plugin_deps]',
              ],
          },
          extras_require={
              'plugin_deps': ['dep1', 'dep2'],
          }
      )

    Therefore, make sure such objects are importable and usable without
    extras. This is necessary, because CLI does the following operations
    (in order):

      - loads an entry point,
      - calls `inject_parser_options`,
      - requires an entry point,
      - creates plugin instance (`__call__`).

    """

    description: str = NotImplemented
    """Short plugin description"""

    @abstractmethod
    def __init__(self, config: Config, name: str):
        """Create new `Plugin`.

        :param Config config: Configuration.
        :param str name: Unique plugin name.

        """
        self.config = config
        self.name = name

    @abstractmethod
    def prepare(self) -> None:
        """Prepare the plugin.

        Finish up any additional initialization.

        :raises .PluginError:
            when full initialization cannot be completed.
        :raises .MisconfigurationError:
            when full initialization cannot be completed. Plugin will
            be displayed on a list of available plugins.
        :raises .NoInstallationError:
            when the necessary programs/files cannot be located. Plugin
            will NOT be displayed on a list of available plugins.
        :raises .NotSupportedError:
            when the installation is recognized, but the version is not
            currently supported.

        """

    @abstractmethod
    def more_info(self) -> str:
        """Human-readable string to help the user.

        Should describe the steps taken and any relevant info to help the user
        decide which plugin to use.

        :rtype str:

        """

    @classmethod
    @abstractmethod
    def inject_parser_options(cls, parser: ArgumentParser, name: str) -> None:
        """Inject argument parser options (flags).

        1. Be nice and prepend all options and destinations with
        `~.common.option_namespace` and `~common.dest_namespace`.

        2. Inject options (flags) only. Positional arguments are not
        allowed, as this would break the CLI.

        :param ArgumentParser parser: (Almost) top-level CLI parser.
        :param str name: Unique plugin name.

        """


class IAuthenticator(IPlugin):
    pass


@zope.interface.implementer(IAuthenticator)
class Authenticator(Plugin):
    """Generic Certbot Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """

    @abstractmethod
    def get_chall_pref(self, domain: str) -> Iterable[Challenge]:
        """Return `collections.Iterable` of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: `collections.Iterable` of challenge types (subclasses of
            :class:`acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: `collections.Iterable`

        """

    @abstractmethod
    def perform(self, achalls: List[AnnotatedChallenge]) -> Iterable[ChallengeResponse]:
        """Perform the given challenge.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, such that it contains types found within
            :func:`get_chall_pref` only.

        :returns: `collections.Iterable` of ACME
            :class:`~acme.challenges.ChallengeResponse` instances corresponding to each provided
            :class:`~acme.challenges.Challenge`.
        :rtype: :class:`collections.Iterable` of
            :class:`acme.challenges.ChallengeResponse`,
            where responses are required to be returned in
            the same order as corresponding input challenges

        :raises .PluginError: If some or all challenges cannot be performed

        """

    @abstractmethod
    def cleanup(self, achalls: List[AnnotatedChallenge]) -> None:
        """Revert changes and shutdown after challenges complete.

        This method should be able to revert all changes made by
        perform, even if perform exited abnormally.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, a subset of those previously passed to :func:`perform`.

        :raises PluginError: if original configuration cannot be restored

        """


class IInstaller(IPlugin):
    pass


@zope.interface.implementer(IInstaller)
class Installer(Plugin):
    """Generic Certbot Installer Interface.

    Represents any server that an X509 certificate can be placed.

    It is assumed that :func:`save` is the only method that finalizes a
    checkpoint. This is important to ensure that checkpoints are
    restored in a consistent manner if requested by the user or in case
    of an error.

    Using :class:`certbot.reverter.Reverter` to implement checkpoints,
    rollback, and recovery can dramatically simplify plugin development.

    """

    @abstractmethod
    def get_all_names(self) -> Iterable[str]:
        """Returns all names that may be authenticated.

        :rtype: `collections.Iterable` of `str`

        """

    @abstractmethod
    def deploy_cert(self, domain: str, cert_path: str, key_path: str,
                    chain_path: str, fullchain_path: str) -> None:
        """Deploy certificate.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        :raises .PluginError: when cert cannot be deployed

        """

    @abstractmethod
    def enhance(self, domain: str, enhancement: str, options: Optional[List[str]] = None) -> None:
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            for expected options for each enhancement.

        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.

        """

    @abstractmethod
    def supported_enhancements(self) -> List[str]:
        """Returns a `collections.Iterable` of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :rtype: :class:`collections.Iterable` of :class:`str`

        """

    @abstractmethod
    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint.

        It is assumed that at most one checkpoint is finalized by this
        method. Additionally, if an exception is raised, it is assumed a
        new checkpoint was not finalized.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises .PluginError: when save is unsuccessful

        """

    @abstractmethod
    def rollback_checkpoints(self, rollback: int = 1) -> None:
        """Revert `rollback` number of configuration checkpoints.

        :raises .PluginError: when configuration cannot be fully reverted

        """

    @abstractmethod
    def recovery_routine(self) -> None:
        """Revert configuration to most recent finalized checkpoint.

        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.

        :raises .errors.PluginError: If unable to recover the configuration

        """

    @abstractmethod
    def config_test(self) -> None:
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: when the config is not in a usable state

        """

    @abstractmethod
    def restart(self) -> None:
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """


class IDisplay(zope.interface.Interface):
    pass


@zope.interface.implementer(IDisplay)
class Display(metaclass=ABCMeta):
    """Generic display."""
    # see https://github.com/certbot/certbot/issues/3915

    @abstractmethod
    def notification(self, message: str, pause: bool, wrap: bool = True,
                     force_interactive: bool = False):
        """Displays a string message

        :param str message: Message to display
        :param bool pause: Whether or not the application should pause for
            confirmation (if available)
        :param bool wrap: Whether or not the application should wrap text
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        """

    @abstractmethod
    def menu(self, message: str, choices: Union[List[str], Tuple[str], str],
             ok_label: Optional[str] = None, cancel_label: Optional[str] = None,
             help_label: Optional[str] = None, default: Optional[int] = None,
             cli_flag: Optional[str] = None, force_interactive: bool = False) -> Tuple[str, int]:
        """Displays a generic menu.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display

        :param choices: choices
        :type choices: :class:`list` of :func:`tuple` or :class:`str`

        :param str ok_label: label for OK button (UNUSED)
        :param str cancel_label: label for Cancel button (UNUSED)
        :param str help_label: label for Help button (UNUSED)
        :param int default: default (non-interactive) choice from the menu
        :param str cli_flag: to automate choice from the menu, eg "--keep"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    @abstractmethod
    def input(self, message: str, default: Optional[str] = None, cli_args: Optional[str] = None,
              force_interactive: bool = False) -> Tuple[str, int]:
        """Accept input from the user.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display to the user
        :param str default: default (non-interactive) response to prompt
        :param str cli_args: to automate choice from the menu, eg "--redirect / --no-redirect"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    @abstractmethod
    def yesno(self, message: str, yes_label: str = "Yes", no_label: str = "No",
              default: Optional[str] = None, cli_args: Optional[str] = None,
              force_interactive: bool = False) -> bool:
        """Query the user with a yes/no question.

        Yes and No label must begin with different letters.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: question for the user
        :param str yes_label: label for Yes button
        :param str no_label: label for No button
        :param str default: default (non-interactive) choice from the menu
        :param str cli_args: to automate choice from the menu, eg "--agree-tos"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: True for "Yes", False for "No"
        :rtype: bool

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    @abstractmethod
    def checklist(self, message: str, tags: List[str], default: Optional[str] = None,
                  cli_args: Optional[str] = None,
                  force_interactive: bool = False) -> Tuple[int, List[str]]:
        """Allow for multiple selections from a menu.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: message to display to the user
        :param list tags: where each is of type :class:`str` len(tags) > 0
        :param str default: default (non-interactive) state of the checklist
        :param str cli_args: to automate choice from the menu, eg "--domains"
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of the form (code, list_tags) where
            `code` - int display exit code
            `list_tags` - list of str tags selected by the user
        :rtype: tuple

        :raises errors.MissingCommandlineFlag: if called in non-interactive
            mode without a default set

        """

    @abstractmethod
    def directory_select(self, message: str, default: Optional[str] = None,
                         cli_flag: Optional[str] = None,
                         force_interactive: bool = False) -> Tuple[int, str]:
        """Display a directory selection screen.

        When not setting force_interactive=True, you must provide a
        default value.

        :param str message: prompt to give the user
        :param default: the default value to return, if one exists, when
            using the NoninteractiveDisplay
        :param str cli_flag: option used to set this value with the CLI,
            if one exists, to be included in error messages given by
            NoninteractiveDisplay
        :param bool force_interactive: True if it's safe to prompt the user
            because it won't cause any workflow regressions

        :returns: tuple of the form (`code`, `string`) where
            `code` - int display exit code
            `string` - input entered by the user

        """


class IReporter(zope.interface.Interface):
    pass


@zope.interface.implementer(IReporter)
class Reporter(metaclass=ABCMeta):
    """Interface to collect and display information to the user."""

    HIGH_PRIORITY: int = 0
    """High priority constant. See `add_message`."""
    MEDIUM_PRIORITY: int = 1
    """Medium priority constant. See `add_message`."""
    LOW_PRIORITY: int = 2
    """Low priority constant. See `add_message`."""

    @abstractmethod
    def add_message(self, msg: str, priority: int, on_crash: bool = True) -> None:
        """Adds msg to the list of messages to be printed.

        :param str msg: Message to be displayed to the user.

        :param int priority: One of HIGH_PRIORITY, MEDIUM_PRIORITY, or
            LOW_PRIORITY.

        :param bool on_crash: Whether or not the message should be printed if
            the program exits abnormally.

        """

    @abstractmethod
    def print_messages(self) -> str:
        """Prints messages to the user and clears the message queue."""


class RenewableCert(object, metaclass=ABCMeta):
    """Interface to a certificate lineage."""

    @property
    @abstractmethod
    def cert_path(self):
        """Path to the certificate file.

        :rtype: str

        """

    @property
    @abstractmethod
    def key_path(self):
        """Path to the private key file.

        :rtype: str

        """

    @property
    @abstractmethod
    def chain_path(self):
        """Path to the certificate chain file.

        :rtype: str

        """

    @property
    @abstractmethod
    def fullchain_path(self):
        """Path to the full chain file.

        The full chain is the certificate file plus the chain file.

        :rtype: str

        """

    @property
    @abstractmethod
    def lineagename(self):
        """Name given to the certificate lineage.

        :rtype: str

        """

    @property
    @abstractmethod
    def names(self):
        """What are the subject names of this certificate?

        :returns: the subject names
        :rtype: `list` of `str`
        :raises .CertStorageError: if could not find cert file.

        """

# Updater interfaces
#
# When "certbot renew" is run, Certbot will iterate over each lineage and check
# if the selected installer for that lineage is a subclass of each updater
# class. If it is and the update of that type is configured to be run for that
# lineage, the relevant update function will be called for it. These functions
# are never called for other subcommands, so if an installer wants to perform
# an update during the run or install subcommand, it should do so when
# :func:`IInstaller.deploy_cert` is called.


class GenericUpdater(metaclass=ABCMeta):
    """Interface for update types not currently specified by Certbot.

    This class allows plugins to perform types of updates that Certbot hasn't
    defined (yet).

    To make use of this interface, the installer should implement the interface
    methods, and interfaces.GenericUpdater.register(InstallerClass) should
    be called from the installer code.

    The plugins implementing this enhancement are responsible of handling
    the saving of configuration checkpoints as well as other calls to
    interface methods of `interfaces.IInstaller` such as prepare() and restart()
    """

    @abstractmethod
    def generic_updates(self, lineage, *args, **kwargs):
        """Perform any update types defined by the installer.

        If an installer is a subclass of the class containing this method, this
        function will always be called when "certbot renew" is run. If the
        update defined by the installer should be run conditionally, the
        installer needs to handle checking the conditions itself.

        This method is called once for each lineage.

        :param lineage: Certificate lineage object
        :type lineage: RenewableCert

        """


class RenewDeployer(metaclass=ABCMeta):
    """Interface for update types run when a lineage is renewed

    This class allows plugins to perform types of updates that need to run at
    lineage renewal that Certbot hasn't defined (yet).

    To make use of this interface, the installer should implement the interface
    methods, and interfaces.RenewDeployer.register(InstallerClass) should
    be called from the installer code.
    """

    @abstractmethod
    def renew_deploy(self, lineage, *args, **kwargs):
        """Perform updates defined by installer when a certificate has been renewed

        If an installer is a subclass of the class containing this method, this
        function will always be called when a certficate has been renewed by
        running "certbot renew". For example if a plugin needs to copy a
        certificate over, or change configuration based on the new certificate.

        This method is called once for each lineage renewed

        :param lineage: Certificate lineage object
        :type lineage: RenewableCert

        """
