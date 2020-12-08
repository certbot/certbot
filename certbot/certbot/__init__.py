"""Certbot client."""
import warnings
import sys

# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '1.11.0.dev0'

if sys.version_info[0] == 2:
    warnings.warn(
        "Python 2 support will be dropped in the next release of Certbot. "
        "Please upgrade your Python version.",
        PendingDeprecationWarning,
    )  # pragma: no cover
