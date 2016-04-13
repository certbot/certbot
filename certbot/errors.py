"""Let's Encrypt client errors."""


class Error(Exception):
    """Generic Let's Encrypt client error."""


class AccountStorageError(Error):
    """Generic `.AccountStorage` error."""


class AccountNotFound(AccountStorageError):
    """Account not found error."""


class ReverterError(Error):
    """Let's Encrypt Reverter error."""


class SubprocessError(Error):
    """Subprocess handling error."""


class CertStorageError(Error):
    """Generic `.CertStorage` error."""


class HookCommandNotFound(Error):
    """Failed to find a hook command in the PATH."""


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
    """Let's Encrypt Plugin error."""


class PluginEnhancementAlreadyPresent(Error):
    """ Enhancement was already set """


class PluginSelectionError(Error):
    """A problem with plugin/configurator selection or setup"""


class NoInstallationError(PluginError):
    """Let's Encrypt No Installation error."""


class MisconfigurationError(PluginError):
    """Let's Encrypt Misconfiguration error."""


class NotSupportedError(PluginError):
    """Let's Encrypt Plugin function not supported error."""


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
