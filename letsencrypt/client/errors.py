"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptReverterError(LetsEncryptClientError):
    """Let's Encrypt Reverter error."""


class LetsEncryptAuthHandlerError(LetsEncryptClientError):
    """Let's Encrypt Auth Handler error."""


class LetsEncryptClientAuthError(LetsEncryptAuthHandlerError):
    """Let's Encrypt Client Authenticator error."""


class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt Configurator error."""


class LetsEncryptNoInstallationError(LetsEncryptConfiguratorError):
    """Let's Encrypt No Installation error."""


class LetsEncryptMisconfigurationError(LetsEncryptConfiguratorError):
    """Let's Encrypt Misconfiguration error."""


class LetsEncryptDvsniError(LetsEncryptConfiguratorError):
    """Let's Encrypt DVSNI error."""


class LetsEncryptValidationError(LetsEncryptClientError):
    pass
