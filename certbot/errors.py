"""Certbot client errors."""


class Error(Exception):
    """Generic Certbot client error."""


class AccountStorageError(Error):
    """Generic `.AccountStorage` error."""


class AccountNotFound(AccountStorageError):
    """Account not found error."""


class ReverterError(Error):
    """Certbot Reverter error."""


class SubprocessError(Error):
    """Subprocess handling error."""


class CertStorageError(Error):
    """Generic `.CertStorage` error."""


class HookCommandNotFound(Error):
    """Failed to find a hook command in the PATH."""


class SignalExit(Error):
    """A Unix signal was received while in the ErrorHandler context manager."""


class LockError(Error):
    """File locking error."""


# Auth Handler Errors
class AuthorizationError(Error):
    """Authorization error."""


class FailedChallenges(AuthorizationError):
    """Failed challenges error.

    :ivar set failed_achalls: Failed `.AnnotatedChallenge` instances.

    """
    def __init__(self, failed_achalls):
        assert failed_achalls
        self.failed_achalls = failed_achalls
        super(FailedChallenges, self).__init__()

    def __str__(self):
        return "Failed authorization procedure. {0}".format(
            ", ".join(
                "{0} ({1}): {2}".format(achall.domain, achall.typ, achall.error)
                for achall in self.failed_achalls if achall.error is not None))


# Plugin Errors
class PluginError(Error):
    """Certbot Plugin error."""


class PluginEnhancementAlreadyPresent(Error):
    """ Enhancement was already set """


class PluginSelectionError(Error):
    """A problem with plugin/configurator selection or setup"""


class NoInstallationError(PluginError):
    """Certbot No Installation error."""


class MisconfigurationError(PluginError):
    """Certbot Misconfiguration error."""


class NotSupportedError(PluginError):
    """Certbot Plugin function not supported error."""


class StandaloneBindError(Error):
    """Standalone plugin bind error."""

    def __init__(self, socket_error, port):
        super(StandaloneBindError, self).__init__(
            "Problem binding to port {0}: {1}".format(port, socket_error))
        self.socket_error = socket_error
        self.port = port


class ConfigurationError(Error):
    """Configuration sanity error."""

# NoninteractiveDisplay iDisplay plugin error:

class MissingCommandlineFlag(Error):
    """A command line argument was missing in noninteractive usage"""
