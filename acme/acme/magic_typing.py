"""Simple shim around the typing module.

This was useful when this code supported Python 2 and typing wasn't always
available. This code is being kept for now for backwards compatibility.

"""
import warnings
from typing import *  # pylint: disable=wildcard-import, unused-wildcard-import
from typing import Any

warnings.warn("acme.magic_typing is deprecated and will be removed in a future release.",
              DeprecationWarning)


class TypingClass:
    """Ignore import errors by getting anything"""
    def __getattr__(self, name: str) -> Any:
        return None  # pragma: no cover
