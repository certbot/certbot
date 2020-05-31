"""
Abstraction of CLI Input.
"""
from abc import ABCMeta, abstractmethod, abstractproperty
from contextlib import contextmanager
from typing import Callable, ContextManager, Generator, List

from prompt_toolkit.key_binding import KeyPress

__all__ = [
    "Input",
    "DummyInput",
]


class Input(metaclass=ABCMeta):
    """
    Abstraction for any input.

    An instance of this class can be given to the constructor of a
    :class:`~prompt_toolkit.application.Application` and will also be
    passed to the :class:`~prompt_toolkit.eventloop.base.EventLoop`.
    """

    @abstractmethod
    def fileno(self) -> int:
        """
        Fileno for putting this in an event loop.
        """

    @abstractmethod
    def typeahead_hash(self) -> str:
        """
        Identifier for storing type ahead key presses.
        """

    @abstractmethod
    def read_keys(self) -> List[KeyPress]:
        """
        Return a list of Key objects which are read/parsed from the input.
        """

    def flush_keys(self) -> List[KeyPress]:
        """
        Flush the underlying parser. and return the pending keys.
        (Used for vt100 input.)
        """
        return []

    def flush(self) -> None:
        " The event loop can call this when the input has to be flushed. "
        pass

    @property
    def responds_to_cpr(self) -> bool:
        """
        `True` if the `Application` can expect to receive a CPR response from
        here.
        """
        return False

    @abstractproperty
    def closed(self) -> bool:
        " Should be true when the input stream is closed. "
        return False

    @abstractmethod
    def raw_mode(self) -> ContextManager[None]:
        """
        Context manager that turns the input into raw mode.
        """

    @abstractmethod
    def cooked_mode(self) -> ContextManager[None]:
        """
        Context manager that turns the input into cooked mode.
        """

    @abstractmethod
    def attach(self, input_ready_callback: Callable[[], None]) -> ContextManager[None]:
        """
        Return a context manager that makes this input active in the current
        event loop.
        """

    @abstractmethod
    def detach(self) -> ContextManager[None]:
        """
        Return a context manager that makes sure that this input is not active
        in the current event loop.
        """

    def close(self) -> None:
        " Close input. "
        pass


class DummyInput(Input):
    """
    Input for use in a `DummyApplication`
    """

    def fileno(self) -> int:
        raise NotImplementedError

    def typeahead_hash(self) -> str:
        return "dummy-%s" % id(self)

    def read_keys(self) -> List[KeyPress]:
        return []

    @property
    def closed(self) -> bool:
        return True

    def raw_mode(self) -> ContextManager[None]:
        return _dummy_context_manager()

    def cooked_mode(self) -> ContextManager[None]:
        return _dummy_context_manager()

    def attach(self, input_ready_callback: Callable[[], None]) -> ContextManager[None]:
        return _dummy_context_manager()

    def detach(self) -> ContextManager[None]:
        return _dummy_context_manager()


@contextmanager
def _dummy_context_manager() -> Generator[None, None, None]:
    yield
