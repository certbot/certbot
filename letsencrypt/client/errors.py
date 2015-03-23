"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptReverterError(LetsEncryptClientError):
    """Let's Encrypt Reverter error."""


# Auth Handler Errors
class LetsEncryptAuthHandlerError(LetsEncryptClientError):
    """Let's Encrypt Auth Handler error."""


class LetsEncryptClientAuthError(LetsEncryptAuthHandlerError):
    """Let's Encrypt Client Authenticator error."""


class LetsEncryptDvAuthError(LetsEncryptAuthHandlerError):
    """Let's Encrypt DV Authenticator error."""


# Authenticator - Challenge specific errors
class LetsEncryptDvsniError(LetsEncryptDvAuthError):
    """Let's Encrypt DVSNI error."""

class LetsEncryptDNSAuthError(LetsEncryptDvAuthError):
    """Let's Encrypt DNS error."""


# Configurator Errors
class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt Configurator error."""


class LetsEncryptNoInstallationError(LetsEncryptConfiguratorError):
    """Let's Encrypt No Installation error."""


class LetsEncryptMisconfigurationError(LetsEncryptConfiguratorError):
    """Let's Encrypt Misconfiguration error."""


class LetsEncryptRevokerError(LetsEncryptClientError):
    """Let's Encrypt Revoker error."""
