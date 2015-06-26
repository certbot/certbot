"""Let's Encrypt client errors."""


class Error(Exception):
    """Generic Let's Encrypt client error."""
LetsEncryptClientError = Error  # TODO: blocked by #485


class ReverterError(Error):
    """Let's Encrypt Reverter error."""


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


class ContAuthError(AuthorizationError):
    """Let's Encrypt Continuity Authenticator error."""


class DvAuthError(AuthorizationError):
    """Let's Encrypt DV Authenticator error."""


# Authenticator - Challenge specific errors
class DvsniError(DvAuthError):
    """Let's Encrypt DVSNI error."""


# Plugin Errors
class PluginError(Error):
    """Let's Encrypt Plugin error."""


class NoInstallationError(PluginError):
    """Let's Encrypt No Installation error."""


class MisconfigurationError(PluginError):
    """Let's Encrypt Misconfiguration error."""


class RevokerError(Error):
    """Let's Encrypt Revoker error."""
