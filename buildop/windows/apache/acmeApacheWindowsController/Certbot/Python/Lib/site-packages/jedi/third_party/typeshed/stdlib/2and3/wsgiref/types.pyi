# Type declaration for a WSGI Function
#
# wsgiref/types.py doesn't exist and neither do the types defined in this
# file. They are provided for type checking purposes.
#
# This means you cannot simply import wsgiref.types in your code. Instead,
# use the `TYPE_CHECKING` flag from the typing module:
#
#   from typing import TYPE_CHECKING
#
#   if TYPE_CHECKING:
#       from wsgiref.types import WSGIApplication
#
# This import is now only taken into account by the type checker. Consequently,
# you need to use 'WSGIApplication' and not simply WSGIApplication when type
# hinting your code.  Otherwise Python will raise NameErrors.

from sys import _OptExcInfo
from typing import Callable, Dict, Iterable, List, Any, Text, Protocol, Tuple, Optional

class StartResponse(Protocol):
    def __call__(self, status: str, headers: List[Tuple[str, str]], exc_info: Optional[_OptExcInfo] = ...) -> Callable[[bytes], Any]: ...

WSGIEnvironment = Dict[Text, Any]
WSGIApplication = Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]

# WSGI input streams per PEP 3333
class InputStream(Protocol):
    def read(self, size: int = ...) -> bytes: ...
    def readline(self, size: int = ...) -> bytes: ...
    def readlines(self, hint: int = ...) -> List[bytes]: ...
    def __iter__(self) -> Iterable[bytes]: ...

# WSGI error streams per PEP 3333
class ErrorStream(Protocol):
    def flush(self) -> None: ...
    def write(self, s: str) -> None: ...
    def writelines(self, seq: List[str]) -> None: ...

class _Readable(Protocol):
    def read(self, size: int = ...) -> bytes: ...
# Optional file wrapper in wsgi.file_wrapper
class FileWrapper(Protocol):
    def __call__(self, file: _Readable, block_size: int = ...) -> Iterable[bytes]: ...
