import io
import sys
from typing import Any, IO, Mapping, Optional, Sequence, Union

if sys.version_info >= (3, 6):
    from os import PathLike
    _PathOrFile = Union[str, bytes, IO[Any], PathLike[Any]]
else:
    _PathOrFile = Union[str, bytes, IO[Any]]

_FilterChain = Sequence[Mapping[str, Any]]

FORMAT_AUTO: int
FORMAT_XZ: int
FORMAT_ALONE: int
FORMAT_RAW: int
CHECK_NONE: int
CHECK_CRC32: int
CHECK_CRC64: int
CHECK_SHA256: int
CHECK_ID_MAX: int
CHECK_UNKNOWN: int
FILTER_LZMA1: int
FILTER_LZMA2: int
FILTER_DELTA: int
FILTER_X86: int
FILTER_IA64: int
FILTER_ARM: int
FILTER_ARMTHUMB: int
FILTER_SPARC: int
FILTER_POWERPC: int
MF_HC3: int
MF_HC4: int
MF_BT2: int
MF_BT3: int
MF_BT4: int
MODE_FAST: int
MODE_NORMAL: int
PRESET_DEFAULT: int
PRESET_EXTREME: int

# from _lzma.c
class LZMADecompressor(object):
    def __init__(self, format: Optional[int] = ..., memlimit: Optional[int] = ..., filters: Optional[_FilterChain] = ...) -> None: ...
    def decompress(self, data: bytes, max_length: int = ...) -> bytes: ...
    @property
    def check(self) -> int: ...
    @property
    def eof(self) -> bool: ...
    @property
    def unused_data(self) -> bytes: ...
    @property
    def needs_input(self) -> bool: ...

# from _lzma.c
class LZMACompressor(object):
    def __init__(self,
                 format: Optional[int] = ...,
                 check: int = ...,
                 preset: Optional[int] = ...,
                 filters: Optional[_FilterChain] = ...) -> None: ...
    def compress(self, data: bytes) -> bytes: ...
    def flush(self) -> bytes: ...


class LZMAError(Exception): ...


class LZMAFile(io.BufferedIOBase, IO[bytes]):  # type: ignore  # python/mypy#5027
    def __init__(self,
                 filename: Optional[_PathOrFile] = ...,
                 mode: str = ...,
                 *,
                 format: Optional[int] = ...,
                 check: int = ...,
                 preset: Optional[int] = ...,
                 filters: Optional[_FilterChain] = ...) -> None: ...
    def close(self) -> None: ...
    @property
    def closed(self) -> bool: ...
    def fileno(self) -> int: ...
    def seekable(self) -> bool: ...
    def readable(self) -> bool: ...
    def writable(self) -> bool: ...
    def peek(self, size: int = ...) -> bytes: ...
    def read(self, size: Optional[int] = ...) -> bytes: ...
    def read1(self, size: int = ...) -> bytes: ...
    def readline(self, size: int = ...) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def seek(self, offset: int, whence: int = ...) -> int: ...
    def tell(self) -> int: ...


def open(filename: _PathOrFile,
         mode: str = ...,
         *,
         format: Optional[int] = ...,
         check: int = ...,
         preset: Optional[int] = ...,
         filters: Optional[_FilterChain] = ...,
         encoding: Optional[str] = ...,
         errors: Optional[str] = ...,
         newline: Optional[str] = ...) -> IO[Any]: ...
def compress(data: bytes, format: int = ..., check: int = ..., preset: Optional[int] = ..., filters: Optional[_FilterChain] = ...) -> bytes: ...
def decompress(data: bytes, format: int = ..., memlimit: Optional[int] = ..., filters: Optional[_FilterChain] = ...) -> bytes: ...
def is_check_supported(check: int) -> bool: ...
