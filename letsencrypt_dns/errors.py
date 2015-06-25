"""Let's Encrypt DNS plugin errors."""
from letsencrypt import errors as core_errors


class Error(core_errors.DvAuthError):
    """Let's Encrypt DNS error."""
