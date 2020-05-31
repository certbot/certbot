import sys


if sys.version_info >= (3, 7):
    from typing import Awaitable, TypeVar

    _T = TypeVar('_T')

    def run(main: Awaitable[_T], *, debug: bool = ...) -> _T: ...
