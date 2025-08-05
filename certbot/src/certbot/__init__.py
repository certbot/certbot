"""Certbot client."""
import sys
import warnings

# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '5.0.0.dev0'


if sys.version_info[:2] == (3, 9):
    warnings.warn(
            "Python 3.9 support will be dropped in the next planned release of "
            "certbot. Please upgrade your Python version.",
            DeprecationWarning,
    )  # pragma: no cover
