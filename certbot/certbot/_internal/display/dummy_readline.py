"""A dummy module with no effect for use on systems without readline."""
from collections.abc import Callable
from collections.abc import Iterable

from typing import Optional


def get_completer() -> Optional[Callable[[], str]]:
    """An empty implementation of readline.get_completer."""


def get_completer_delims() -> list[str]:
    """An empty implementation of readline.get_completer_delims."""
    return []


def parse_and_bind(unused_command: str) -> None:
    """An empty implementation of readline.parse_and_bind."""


def set_completer(unused_function: Optional[Callable[[], str]] = None) -> None:
    """An empty implementation of readline.set_completer."""


def set_completer_delims(unused_delims: Iterable[str]) -> None:
    """An empty implementation of readline.set_completer_delims."""
