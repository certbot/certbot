"""Certbot client."""
import warnings
import sys

# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '1.7.0'

if sys.version_info[:2] == (3, 5):
    warnings.warn(
            "Python 3.5 support will be dropped in the next release of "
            "certbot. Please upgrade your Python version.",
            PendingDeprecationWarning,
    )  # pragma: no cover
