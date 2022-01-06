"""Certbot client."""
# version number like 1.2.3a0, must have at least 2 parts, like 1.2
import sys
import warnings

__version__ = '1.23.0.dev0'

if sys.version_info[:2] == (3, 6):
    warnings.warn(
            "Python 3.6 support will be dropped in the next release of "
            "certbot. Please upgrade your Python version.",
            PendingDeprecationWarning,
    )  # pragma: no cover
