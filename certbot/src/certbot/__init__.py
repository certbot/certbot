"""Certbot client."""
import sys
import warnings

# version number like 1.2.3a0, must have at least 2 parts, like 1.2
__version__ = '5.9.0.dev0'

if sys.version_info[:2] == (3, 10):
    warnings.warn(
        "Python 3.10 support will be dropped in the next major release "
        "of Certbot. Please upgrade your Python version.",
        DeprecationWarning
    )
