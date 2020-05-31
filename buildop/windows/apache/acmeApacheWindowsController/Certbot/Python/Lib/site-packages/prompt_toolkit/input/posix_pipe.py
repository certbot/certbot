import os
from typing import ContextManager, TextIO, cast

from ..utils import DummyContext
from .vt100 import Vt100Input

__all__ = [
    "PosixPipeInput",
]


class PosixPipeInput(Vt100Input):
    """
    Input that is send through a pipe.
    This is useful if we want to send the input programmatically into the
    application. Mostly useful for unit testing.

    Usage::

        input = PosixPipeInput()
        input.send_text('inputdata')
    """

    _id = 0

    def __init__(self, text: str = "") -> None:
        self._r, self._w = os.pipe()

        class Stdin:
            def isatty(stdin) -> bool:
                return True

            def fileno(stdin) -> int:
                return self._r

        super().__init__(cast(TextIO, Stdin()))
        self.send_text(text)

        # Identifier for every PipeInput for the hash.
        self.__class__._id += 1
        self._id = self.__class__._id

    @property
    def responds_to_cpr(self) -> bool:
        return False

    def send_bytes(self, data: bytes) -> None:
        os.write(self._w, data)

    def send_text(self, data: str) -> None:
        " Send text to the input. "
        os.write(self._w, data.encode("utf-8"))

    def raw_mode(self) -> ContextManager[None]:
        return DummyContext()

    def cooked_mode(self) -> ContextManager[None]:
        return DummyContext()

    def close(self) -> None:
        " Close pipe fds. "
        os.close(self._r)
        os.close(self._w)

        # We should assign `None` to 'self._r` and 'self._w',
        # The event loop still needs to know the the fileno for this input in order
        # to properly remove it from the selectors.

    def typeahead_hash(self) -> str:
        """
        This needs to be unique for every `PipeInput`.
        """
        return "pipe-input-%s" % (self._id,)
