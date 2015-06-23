"""Let's Encrypt client errors."""


class Error(Exception):
    """Generic Let's Encrypt client error."""
LetsEncryptClientError = Error  # TODO: blocked by #485


class ReverterError(Error):
    """Let's Encrypt Reverter error."""


# Auth Handler Errors
class AuthorizationError(Error):
    """Authorization error."""


class ContAuthError(AuthorizationError):
    """Let's Encrypt Continuity Authenticator error."""


class DvAuthError(AuthorizationError):
    """Let's Encrypt DV Authenticator error."""


# Authenticator - Challenge specific errors
class DvsniError(DvAuthError):
    """Let's Encrypt DVSNI error."""


# Configurator Errors
class ConfiguratorError(Error):
    """Let's Encrypt Configurator error."""


class NoInstallationError(ConfiguratorError):
    """Let's Encrypt No Installation error."""


class MisconfigurationError(ConfiguratorError):
    """Let's Encrypt Misconfiguration error."""


class RevokerError(Error):
    """Let's Encrypt Revoker error."""
