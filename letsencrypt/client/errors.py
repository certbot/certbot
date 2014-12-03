"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptConfiguratorError(LetsEncryptClientError):
    """Let's Encrypt configurator error."""


class LetsEncryptDvsniError(LetsEncryptConfiguratorError):
    """Let's Encrypt DVSNI error."""
