"""Let's Encrypt client errors."""


class Error(Exception):
    """Generic Let's Encrypt client error."""


class ReverterError(Error):
    """Reverter error."""


# Auth Handler Errors
class AuthHandlerError(Error):
    """Auth Handler error."""


class ClientAuthError(AuthHandlerError):
    """Client Authenticator error."""


class DvAuthError(AuthHandlerError):
    """DV Authenticator error."""


# Authenticator - Challenge specific errors
class DvsniError(DvAuthError):
    """DVSNI error."""


# Configurator Errors
class ConfiguratorError(Error):
    """Configurator error."""


class NoInstallationError(ConfiguratorError):
    """No Installation error."""


class MisconfigurationError(ConfiguratorError):
    """Misconfiguration error."""


class RevokerError(Error):
    """Let's Encrypt Revoker error."""
