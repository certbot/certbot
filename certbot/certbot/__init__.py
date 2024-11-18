"""Certbot client."""
import sys
import warnings

# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '3.0.1'

if sys.version_info[:2] == (3, 8):
    warnings.warn(
            "Python 3.8 support will be dropped in the next planned release of "
            "certbot. Please upgrade your Python version.",
            PendingDeprecationWarning,
    )  # pragma: no cover
