"""Let's Encrypt client errors."""


class LetsEncryptClientError(Exception):
    """Generic Let's Encrypt client error."""


class LetsEncryptDvsniError(Exception):
    """Let's Encrypt DVSNI error."""
