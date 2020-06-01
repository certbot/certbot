import sys
from typing import Any, IO, Optional, Tuple, Callable, Dict, List, Union, Protocol, Type

from .decoder import JSONDecoder as JSONDecoder
from .encoder import JSONEncoder as JSONEncoder
from .decoder import JSONDecodeError as JSONDecodeError

def dumps(obj: Any,
          skipkeys: bool = ...,
          ensure_ascii: bool = ...,
          check_circular: bool = ...,
          allow_nan: bool = ...,
          cls: Optional[Type[JSONEncoder]] = ...,
          indent: Union[None, int, str] = ...,
          separators: Optional[Tuple[str, str]] = ...,
          default: Optional[Callable[[Any], Any]] = ...,
          sort_keys: bool = ...,
          **kwds: Any) -> str: ...

def dump(obj: Any,
         fp: IO[str],
         skipkeys: bool = ...,
         ensure_ascii: bool = ...,
         check_circular: bool = ...,
         allow_nan: bool = ...,
         cls: Optional[Type[JSONEncoder]] = ...,
         indent: Union[None, int, str] = ...,
         separators: Optional[Tuple[str, str]] = ...,
         default: Optional[Callable[[Any], Any]] = ...,
         sort_keys: bool = ...,
         **kwds: Any) -> None: ...

if sys.version_info >= (3, 6):
    _LoadsString = Union[str, bytes, bytearray]
else:
    _LoadsString = str
def loads(s: _LoadsString,
          encoding: Any = ...,  # ignored and deprecated
          cls: Optional[Type[JSONDecoder]] = ...,
          object_hook: Optional[Callable[[Dict[Any, Any]], Any]] = ...,
          parse_float: Optional[Callable[[str], Any]] = ...,
          parse_int: Optional[Callable[[str], Any]] = ...,
          parse_constant: Optional[Callable[[str], Any]] = ...,
          object_pairs_hook: Optional[Callable[[List[Tuple[Any, Any]]], Any]] = ...,
          **kwds: Any) -> Any: ...

class _Reader(Protocol):
    def read(self) -> _LoadsString: ...

def load(fp: _Reader,
         cls: Optional[Type[JSONDecoder]] = ...,
         object_hook: Optional[Callable[[Dict[Any, Any]], Any]] = ...,
         parse_float: Optional[Callable[[str], Any]] = ...,
         parse_int: Optional[Callable[[str], Any]] = ...,
         parse_constant: Optional[Callable[[str], Any]] = ...,
         object_pairs_hook: Optional[Callable[[List[Tuple[Any, Any]]], Any]] = ...,
         **kwds: Any) -> Any: ...
