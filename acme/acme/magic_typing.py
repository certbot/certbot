"""Shim class to not have to depend on typing module in prod."""
import sys

class TypingClass(object):
    """Ignore import errors by getting anything"""
    def __getattr__(self, name):
        return None

try:
    # mypy doesn't respect modifying sys.modules
    from typing import *
    # cache into sys.modules for when we're actually running
    import typing
    sys.modules[__name__] = typing
except ImportError:
    sys.modules[__name__] = TypingClass()
