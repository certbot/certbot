"""Let's Encrypt client errors."""


class ClientError(Exception):
    """Generic Let's Encrypt client error."""


class ReverterError(ClientError):
    """Reverter error."""


# Auth Handler Errors
class AuthHandlerError(ClientError):
    """Auth Handler error."""


class ClientAuthError(AuthHandlerError):
    """Client Authenticator error."""


class DvAuthError(AuthHandlerError):
    """DV Authenticator error."""


# Authenticator - Challenge specific errors
class DvsniError(DvAuthError):
    """DVSNI error."""


# Configurator Errors
class ConfiguratorError(ClientError):
    """Configurator error."""


class NoInstallationError(ConfiguratorError):
    """No Installation error."""


class MisconfigurationError(ConfiguratorError):
    """Misconfiguration error."""

