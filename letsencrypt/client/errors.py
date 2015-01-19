"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptReverterError(LetsEncryptClientError):
    """Let's Encrypt Reverter error."""


class LetsEncryptAuthHandlerError(LetsEncryptClientError):
    """Let's Encrypt Auth Handler error."""


class LetsEncryptClientAuthError(LetsEncryptAuthHandlerError):
    """Let's Encrypt Client Authenticator Error."""


class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt Configurator error."""


class LetsEncryptMisconfigurationError(LetsEncryptClientError):
    """Let's Encrypt Misconfiguration Error."""


class LetsEncryptDvsniError(LetsEncryptConfiguratorError):
    """Let's Encrypt DVSNI error."""
