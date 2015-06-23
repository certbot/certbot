"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptReverterError(LetsEncryptClientError):
    """Let's Encrypt Reverter error."""


# Auth Handler Errors
class AuthorizationError(LetsEncryptClientError):
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


class LetsEncryptContAuthError(AuthorizationError):
    """Let's Encrypt Continuity Authenticator error."""


class LetsEncryptDvAuthError(AuthorizationError):
    """Let's Encrypt DV Authenticator error."""


# Authenticator - Challenge specific errors
class LetsEncryptDvsniError(LetsEncryptDvAuthError):
    """Let's Encrypt DVSNI error."""


# Configurator Errors
class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt Configurator error."""


class LetsEncryptNoInstallationError(LetsEncryptConfiguratorError):
    """Let's Encrypt No Installation error."""


class LetsEncryptMisconfigurationError(LetsEncryptConfiguratorError):
    """Let's Encrypt Misconfiguration error."""


class LetsEncryptRevokerError(LetsEncryptClientError):
    """Let's Encrypt Revoker error."""
