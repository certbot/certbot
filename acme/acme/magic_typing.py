"""Shim class to not have to depend on typing module in prod."""
import sys


class TypingClass(object):
    """Ignore import errors by getting anything"""
    def __getattr__(self, name):
        return None

try:
    # mypy doesn't respect modifying sys.modules
    from typing import *  # pylint: disable=wildcard-import, unused-wildcard-import
    from typing import Collection, IO  # type: ignore
except ImportError:
    # mypy complains because TypingClass is not a module
    sys.modules[__name__] = TypingClass()  # type: ignore
