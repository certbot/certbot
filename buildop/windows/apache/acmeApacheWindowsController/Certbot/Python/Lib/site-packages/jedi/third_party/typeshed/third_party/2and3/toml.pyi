from typing import Any, IO, List, Mapping, MutableMapping, Optional, Protocol, Text, Type, Union
import datetime
import sys

if sys.version_info >= (3, 4):
    import pathlib
    if sys.version_info >= (3, 6):
        import os
        _PathLike = Union[Text, pathlib.PurePath, os.PathLike]
    else:
        _PathLike = Union[Text, pathlib.PurePath]
else:
    _PathLike = Text

class _Writable(Protocol):
    def write(self, obj: str) -> Any: ...

class TomlDecodeError(Exception): ...

def load(f: Union[_PathLike, List[Text], IO[str]], _dict: Type[MutableMapping[str, Any]] = ...) -> MutableMapping[str, Any]: ...
def loads(s: Text, _dict: Type[MutableMapping[str, Any]] = ...) -> MutableMapping[str, Any]: ...

def dump(o: Mapping[str, Any], f: _Writable) -> str: ...
def dumps(o: Mapping[str, Any]) -> str: ...
