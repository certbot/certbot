"""Certbot client interfaces."""
from abc import ABCMeta
from abc import abstractmethod
from argparse import ArgumentParser
import sys
from types import ModuleType
from typing import Any
from typing import Union
from typing import cast
from typing import Iterable
from typing import List
from typing import Optional
from typing import Type
from typing import TYPE_CHECKING
import warnings

import zope.interface

from acme.challenges import Challenge
from acme.challenges import ChallengeResponse
from acme.client import ClientBase
from certbot import configuration
from certbot.achallenges import AnnotatedChallenge

if TYPE_CHECKING:
    from certbot._internal.account import Account


class AccountStorage(metaclass=ABCMeta):
    """Accounts storage interface."""

    @abstractmethod
    def find_all(self) -> List['Account']:  # pragma: no cover
        """Find all accounts.

        :returns: All found accounts.
        :rtype: list

        """
        raise NotImplementedError()

    @abstractmethod
    def load(self, account_id: str) -> 'Account':  # pragma: no cover
        """Load an account by its id.

        :raises .AccountNotFound: if account could not be found
        :raises .AccountStorageError: if account could not be loaded

        :returns: The account loaded
        :rtype: .Account

        """
        raise NotImplementedError()

    @abstractmethod
    def save(self, account: 'Account', client: ClientBase) -> None:  # pragma: no cover
        """Save account.

        :raises .AccountStorageError: if account could not be saved

        """
        raise NotImplementedError()


class IConfig(zope.interface.Interface):  # pylint: disable=inherit-non-class
    """Deprecated, use certbot.configuration.NamespaceConfig instead."""


class IPluginFactory(zope.interface.Interface):  # pylint: disable=inherit-non-class
    """Deprecated, use certbot.interfaces.Plugin as ABC instead."""


class IPlugin(zope.interface.Interface):  # pylint: disable=inherit-non-class
    """Deprecated, use certbot.interfaces.Plugin as ABC instead."""


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

    name: str = NotImplemented
    """Unique name of the plugin"""

    @abstractmethod
    def __init__(self, config: Optional[configuration.NamespaceConfig], name: str) -> None:
        """Create a new `Plugin`.

        :param configuration.NamespaceConfig config: Configuration.
        :param str name: Unique plugin name.

        """
        super().__init__()

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


class IAuthenticator(IPlugin):  # pylint: disable=inherit-non-class
    """Deprecated, use certbot.interfaces.Authenticator as ABC instead."""


class Authenticator(Plugin):
    """Generic Certbot Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """

    @abstractmethod
    def get_chall_pref(self, domain: str) -> Iterable[Type[Challenge]]:
        """Return `collections.Iterable` of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: `collections.Iterable` of challenge types (subclasses of
            :class:`acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: `collections.Iterable`

        """

    @abstractmethod
    def perform(self, achalls: List[AnnotatedChallenge]) -> List[ChallengeResponse]:
        """Perform the given challenge.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, such that it contains types found within
            :func:`get_chall_pref` only.

        :returns: list of ACME
            :class:`~acme.challenges.ChallengeResponse` instances corresponding to each provided
            :class:`~acme.challenges.Challenge`.
        :rtype: :class:`collections.List` of
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


class IInstaller(IPlugin):  # pylint: disable=inherit-non-class
    """Deprecated, use certbot.interfaces.Installer as ABC instead."""


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
    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[List[str], str]] = None) -> None:
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


class IDisplay(zope.interface.Interface):  # pylint: disable=inherit-non-class
    """Deprecated, use your own Display implementation instead."""


class IReporter(zope.interface.Interface):  # pylint: disable=inherit-non-class
    """Deprecated, use your own Reporter implementation instead."""


class RenewableCert(metaclass=ABCMeta):
    """Interface to a certificate lineage."""

    @property
    @abstractmethod
    def cert_path(self) -> str:
        """Path to the certificate file.

        :rtype: str

        """

    @property
    @abstractmethod
    def key_path(self) -> str:
        """Path to the private key file.

        :rtype: str

        """

    @property
    @abstractmethod
    def chain_path(self) -> str:
        """Path to the certificate chain file.

        :rtype: str

        """

    @property
    @abstractmethod
    def fullchain_path(self) -> str:
        """Path to the full chain file.

        The full chain is the certificate file plus the chain file.

        :rtype: str

        """

    @property
    @abstractmethod
    def lineagename(self) -> str:
        """Name given to the certificate lineage.

        :rtype: str

        """

    @abstractmethod
    def names(self) -> List[str]:
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
    interface methods of `interfaces.Installer` such as prepare() and restart()
    """

    @abstractmethod
    def generic_updates(self, lineage: RenewableCert, *args: Any, **kwargs: Any) -> None:
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
    def renew_deploy(self, lineage: RenewableCert, *args: Any, **kwargs: Any) -> None:
        """Perform updates defined by installer when a certificate has been renewed

        If an installer is a subclass of the class containing this method, this
        function will always be called when a certificate has been renewed by
        running "certbot renew". For example if a plugin needs to copy a
        certificate over, or change configuration based on the new certificate.

        This method is called once for each lineage renewed

        :param lineage: Certificate lineage object
        :type lineage: RenewableCert

        """


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _ZopeInterfacesDeprecationModule:
    """
    Internal class delegating to a module, and displaying warnings when
    attributes related to Zope interfaces are accessed.
    """
    def __init__(self, module: ModuleType) -> None:
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> None:
        if attr in ('IConfig', 'IPlugin', 'IPluginFactory', 'IAuthenticator',
                    'IInstaller', 'IDisplay', 'IReporter'):
            warnings.warn('{0} attribute in certbot.interfaces module is deprecated '
                          'and will be removed soon.'.format(attr),
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> None:  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self) -> List[str]:  # pragma: no cover
        return ['_module'] + dir(self._module)


# Patching ourselves to warn about Zope interfaces deprecation and planned removal.
sys.modules[__name__] = cast(ModuleType, _ZopeInterfacesDeprecationModule(sys.modules[__name__]))
