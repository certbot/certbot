"""Shim class to not have to depend on typing module in prod."""
import sys


class TypingClass(object):
    """Ignore import errors by getting anything"""
    def __getattr__(self, name):
        return None


try:
    # mypy doesn't respect modifying sys.modules
    from typing import *  # noqa: F401,F403
except ImportError:
    sys.modules[__name__] = TypingClass()
