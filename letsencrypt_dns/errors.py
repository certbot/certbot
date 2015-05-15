"""Let's Encrypt DNS plugin errors."""
from letsencrypt import errors as core_errors


class Error(core_errors.LetsEncryptDvAuthError):
    """Let's Encrypt DNS error."""
