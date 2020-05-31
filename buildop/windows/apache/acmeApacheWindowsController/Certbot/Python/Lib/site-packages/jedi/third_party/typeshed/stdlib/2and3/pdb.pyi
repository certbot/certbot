# NOTE: This stub is incomplete - only contains some global functions

from cmd import Cmd
import sys
from types import FrameType
from typing import Any, Callable, Dict, IO, Iterable, Optional, TypeVar

_T = TypeVar('_T')

class Restart(Exception): ...

def run(statement: str, globals: Optional[Dict[str, Any]] = ...,
        locals: Optional[Dict[str, Any]] = ...) -> None: ...
def runeval(expression: str, globals: Optional[Dict[str, Any]] = ...,
            locals: Optional[Dict[str, Any]] = ...) -> Any: ...
def runctx(statement: str, globals: Dict[str, Any], locals: Dict[str, Any]) -> None: ...
def runcall(*args: Any, **kwds: Any) -> Any: ...

if sys.version_info >= (3, 7):
    def set_trace(*, header: Optional[str] = ...) -> None: ...
else:
    def set_trace() -> None: ...

def post_mortem(t: Optional[Any] = ...) -> None: ...
def pm() -> None: ...

class Pdb(Cmd):
    if sys.version_info >= (3, 6):
        def __init__(
            self,
            completekey: str = ...,
            stdin: Optional[IO[str]] = ...,
            stdout: Optional[IO[str]] = ...,
            skip: Optional[Iterable[str]] = ...,
            nosigint: bool = ...,
            readrc: bool = ...,
        ) -> None: ...
    elif sys.version_info >= (3, 2):
        def __init__(
            self,
            completekey: str = ...,
            stdin: Optional[IO[str]] = ...,
            stdout: Optional[IO[str]] = ...,
            skip: Optional[Iterable[str]] = ...,
            nosigint: bool = ...,
        ) -> None: ...
    else:
        def __init__(
            self,
            completekey: str = ...,
            stdin: Optional[IO[str]] = ...,
            stdout: Optional[IO[str]] = ...,
            skip: Optional[Iterable[str]] = ...,
        ) -> None: ...
    # TODO: The run* and set_trace() methods are actually defined on bdb.Bdb, from which Pdb inherits.
    # Move these methods there once we have a bdb stub.
    def run(self, statement: str, globals: Optional[Dict[str, Any]] = ...,
            locals: Optional[Dict[str, Any]] = ...) -> None: ...
    def runeval(self, expression: str, globals: Optional[Dict[str, Any]] = ...,
                locals: Optional[Dict[str, Any]] = ...) -> Any: ...
    def runcall(self, func: Callable[..., _T], *args: Any, **kwds: Any) -> Optional[_T]: ...
    def set_trace(self, frame: Optional[FrameType] = ...) -> None: ...
