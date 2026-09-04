"""Deprecated tools for checking certificate revocation."""
import warnings

# ruff: disable[F403]
from certbot._internal.ocsp import *  # pylint: disable=wildcard-import,unused-wildcard-import
# ruff: enable[F403]

warnings.warn("certbot.ocsp is deprecated and will be removed in the next major"
              " release", DeprecationWarning, stacklevel=2)
