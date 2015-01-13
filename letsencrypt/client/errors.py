"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptAuthHandlerError(LetsEncryptClientError):
    """Let's Encrypt Auth Handler error."""


class LetsEncryptClientAuthError(LetsEncryptAuthHandlerError):
    """Let's Encrypt Client Authenticator Error."""


class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt Configurator error."""


class LetsEncryptDvsniError(LetsEncryptConfiguratorError):
    """Let's Encrypt DVSNI error."""
