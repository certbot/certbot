# Stubs for tempfile
# Ron Murawski <ron@horizonchess.com>

# based on http://docs.python.org/3.3/library/tempfile.html

import os
import sys
from types import TracebackType
from typing import Any, AnyStr, Generic, IO, Iterable, Iterator, List, Optional, overload, Tuple, Type, TypeVar, Union

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

# global variables
TMP_MAX: int
tempdir: Optional[str]
template: str

_S = TypeVar("_S")
_T = TypeVar("_T")  # for pytype, define typevar in same file as alias
if sys.version_info >= (3, 6):
    _DirT = Union[_T, os.PathLike[_T]]
else:
    _DirT = Union[_T]

@overload
def TemporaryFile(
    mode: Literal["r", "w", "a", "x", "r+", "w+", "a+", "x+", "rt", "wt", "at", "xt", "r+t", "w+t", "a+t", "x+t"],
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
) -> IO[str]: ...
@overload
def TemporaryFile(
    mode: Literal["rb", "wb", "ab", "xb", "r+b", "w+b", "a+b", "x+b"] = ...,
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
) -> IO[bytes]: ...
@overload
def TemporaryFile(
    mode: str = ...,
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
) -> IO[Any]: ...
@overload
def NamedTemporaryFile(
    mode: Literal["r", "w", "a", "x", "r+", "w+", "a+", "x+", "rt", "wt", "at", "xt", "r+t", "w+t", "a+t", "x+t"],
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
    delete: bool = ...,
) -> IO[str]: ...
@overload
def NamedTemporaryFile(
    mode: Literal["rb", "wb", "ab", "xb", "r+b", "w+b", "a+b", "x+b"] = ...,
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
    delete: bool = ...,
) -> IO[bytes]: ...
@overload
def NamedTemporaryFile(
    mode: str = ...,
    buffering: int = ...,
    encoding: Optional[str] = ...,
    newline: Optional[str] = ...,
    suffix: Optional[AnyStr] = ...,
    prefix: Optional[AnyStr] = ...,
    dir: Optional[_DirT[AnyStr]] = ...,
    delete: bool = ...,
) -> IO[Any]: ...

# It does not actually derive from IO[AnyStr], but it does implement the
# protocol.
class SpooledTemporaryFile(IO[AnyStr]):
    # bytes needs to go first, as default mode is to open as bytes
    @overload
    def __init__(
        self: SpooledTemporaryFile[bytes],
        max_size: int = ...,
        mode: Literal["rb", "wb", "ab", "xb", "r+b", "w+b", "a+b", "x+b"] = ...,
        buffering: int = ...,
        encoding: Optional[str] = ...,
        newline: Optional[str] = ...,
        suffix: Optional[str] = ...,
        prefix: Optional[str] = ...,
        dir: Optional[str] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self: SpooledTemporaryFile[str],
        max_size: int = ...,
        mode: Literal["r", "w", "a", "x", "r+", "w+", "a+", "x+", "rt", "wt", "at", "xt", "r+t", "w+t", "a+t", "x+t"] = ...,
        buffering: int = ...,
        encoding: Optional[str] = ...,
        newline: Optional[str] = ...,
        suffix: Optional[str] = ...,
        prefix: Optional[str] = ...,
        dir: Optional[str] = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        max_size: int = ...,
        mode: str = ...,
        buffering: int = ...,
        encoding: Optional[str] = ...,
        newline: Optional[str] = ...,
        suffix: Optional[str] = ...,
        prefix: Optional[str] = ...,
        dir: Optional[str] = ...,
    ) -> None: ...
    def rollover(self) -> None: ...
    def __enter__(self: _S) -> _S: ...
    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> Optional[bool]: ...
    # These methods are copied from the abstract methods of IO, because
    # SpooledTemporaryFile implements IO.
    # See also https://github.com/python/typeshed/pull/2452#issuecomment-420657918.
    def close(self) -> None: ...
    def fileno(self) -> int: ...
    def flush(self) -> None: ...
    def isatty(self) -> bool: ...
    def read(self, n: int = ...) -> AnyStr: ...
    def readable(self) -> bool: ...
    def readline(self, limit: int = ...) -> AnyStr: ...
    def readlines(self, hint: int = ...) -> List[AnyStr]: ...
    def seek(self, offset: int, whence: int = ...) -> int: ...
    def seekable(self) -> bool: ...
    def tell(self) -> int: ...
    def truncate(self, size: Optional[int] = ...) -> int: ...
    def writable(self) -> bool: ...
    def write(self, s: AnyStr) -> int: ...
    def writelines(self, lines: Iterable[AnyStr]) -> None: ...
    def __next__(self) -> AnyStr: ...
    def __iter__(self) -> Iterator[AnyStr]: ...

class TemporaryDirectory(Generic[AnyStr]):
    name: str
    def __init__(
        self, suffix: Optional[AnyStr] = ..., prefix: Optional[AnyStr] = ..., dir: Optional[_DirT[AnyStr]] = ...
    ) -> None: ...
    def cleanup(self) -> None: ...
    def __enter__(self) -> AnyStr: ...
    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None: ...

def mkstemp(
    suffix: Optional[AnyStr] = ..., prefix: Optional[AnyStr] = ..., dir: Optional[_DirT[AnyStr]] = ..., text: bool = ...
) -> Tuple[int, AnyStr]: ...
@overload
def mkdtemp() -> str: ...
@overload
def mkdtemp(suffix: Optional[AnyStr] = ..., prefix: Optional[AnyStr] = ..., dir: Optional[_DirT[AnyStr]] = ...) -> AnyStr: ...
def mktemp(suffix: Optional[AnyStr] = ..., prefix: Optional[AnyStr] = ..., dir: Optional[_DirT[AnyStr]] = ...) -> AnyStr: ...
def gettempdirb() -> bytes: ...
def gettempprefixb() -> bytes: ...
def gettempdir() -> str: ...
def gettempprefix() -> str: ...
