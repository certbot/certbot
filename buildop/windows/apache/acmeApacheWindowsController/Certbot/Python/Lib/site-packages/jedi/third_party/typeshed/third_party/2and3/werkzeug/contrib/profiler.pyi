from typing import Any, AnyStr, Generic, Optional, Protocol, Tuple, TypeVar

from ..middleware.profiler import *

_T = TypeVar("_T")
_T_contra = TypeVar("_T_contra", contravariant=True)

class _Writable(Protocol[_T_contra]):
    def write(self, __s: _T_contra) -> Any: ...

class MergeStream(Generic[_T]):
    streams: Tuple[_Writable[_T], ...]
    def __init__(self, *streams: _Writable[_T]) -> None: ...
    def write(self, data: _T) -> None: ...
