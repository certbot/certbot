"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptDvsniError(LetsEncryptClientError):
    """Let's Encrypt DVSNI error."""
