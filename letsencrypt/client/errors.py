"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class NetworkError(LetsEncryptClientError):
    """Network error."""


class UnexpectedUpdate(NetworkError):
    """Unexpected update."""


class LetsEncryptReverterError(LetsEncryptClientError):
    """Let's Encrypt Reverter error."""


# Auth Handler Errors
class AuthHandlerError(LetsEncryptClientError):
    """Auth Handler error."""


class LetsEncryptContAuthError(AuthHandlerError):
    """Let's Encrypt Client Authenticator error."""


class LetsEncryptDvAuthError(AuthHandlerError):
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
