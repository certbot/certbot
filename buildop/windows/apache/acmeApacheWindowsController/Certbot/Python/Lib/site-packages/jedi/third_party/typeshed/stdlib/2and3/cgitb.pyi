
from typing import Dict, Any, List, Tuple, Optional, Callable, Type, Union, IO, AnyStr, TypeVar
from types import FrameType, TracebackType
import sys


_T = TypeVar("_T")
_ExcInfo = Tuple[Optional[Type[BaseException]], Optional[BaseException], Optional[TracebackType]]
if sys.version_info >= (3, 6):
    from os import PathLike
    _Path = Union[_T, PathLike[_T]]
else:
    _Path = Union[_T]


def reset() -> str: ...  # undocumented
def small(text: str) -> str: ...  # undocumented
def strong(text: str) -> str: ...  # undocumented
def grey(text: str) -> str: ...  # undocumented
def lookup(name: str, frame: FrameType, locals: Dict[str, Any]) -> Tuple[Optional[str], Any]: ...  # undocumented
def scanvars(reader: Callable[[], bytes], frame: FrameType, locals: Dict[str, Any]) -> List[Tuple[str, Optional[str], Any]]: ...  # undocumented
def html(einfo: _ExcInfo, context: int = ...) -> str: ...
def text(einfo: _ExcInfo, context: int = ...) -> str: ...

class Hook:  # undocumented

    def __init__(self, display: int = ..., logdir: Optional[_Path[AnyStr]] = ..., context: int = ..., file: Optional[IO[str]] = ..., format: str = ...) -> None: ...
    def __call__(self, etype: Optional[Type[BaseException]], evalue: Optional[BaseException], etb: Optional[TracebackType]) -> None: ...
    def handle(self, info: Optional[_ExcInfo] = ...) -> None: ...

def handler(info: Optional[_ExcInfo] = ...) -> None: ...

def enable(display: int = ..., logdir: Optional[_Path[AnyStr]] = ..., context: int = ..., format: str = ...) -> None: ...
