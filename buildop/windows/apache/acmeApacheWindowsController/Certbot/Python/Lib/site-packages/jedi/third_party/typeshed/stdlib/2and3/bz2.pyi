import io
import sys
from typing import Any, IO, Optional, Union

if sys.version_info >= (3, 6):
    from os import PathLike
    _PathOrFile = Union[str, bytes, IO[Any], PathLike[Any]]
elif sys.version_info >= (3, 3):
    _PathOrFile = Union[str, bytes, IO[Any]]
else:
    _PathOrFile = str

def compress(data: bytes, compresslevel: int = ...) -> bytes: ...
def decompress(data: bytes) -> bytes: ...

if sys.version_info >= (3, 3):
    def open(filename: _PathOrFile,
             mode: str = ...,
             compresslevel: int = ...,
             encoding: Optional[str] = ...,
             errors: Optional[str] = ...,
             newline: Optional[str] = ...) -> IO[Any]: ...

class BZ2File(io.BufferedIOBase, IO[bytes]):  # type: ignore  # python/mypy#5027
    def __init__(self,
                 filename: _PathOrFile,
                 mode: str = ...,
                 buffering: Optional[Any] = ...,
                 compresslevel: int = ...) -> None: ...

class BZ2Compressor(object):
    def __init__(self, compresslevel: int = ...) -> None: ...
    def compress(self, data: bytes) -> bytes: ...
    def flush(self) -> bytes: ...

class BZ2Decompressor(object):
    if sys.version_info >= (3, 5):
        def decompress(self, data: bytes, max_length: int = ...) -> bytes: ...
    else:
        def decompress(self, data: bytes) -> bytes: ...
    if sys.version_info >= (3, 3):
        @property
        def eof(self) -> bool: ...
    if sys.version_info >= (3, 5):
        @property
        def needs_input(self) -> bool: ...
    @property
    def unused_data(self) -> bytes: ...
