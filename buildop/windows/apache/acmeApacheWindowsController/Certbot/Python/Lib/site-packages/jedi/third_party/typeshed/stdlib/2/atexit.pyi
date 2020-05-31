from typing import TypeVar, Any

_FT = TypeVar('_FT')

def register(func: _FT, *args: Any, **kargs: Any) -> _FT: ...
