# Source: https://hg.python.org/cpython/file/2.7/Lib/sre_compile.py
# and https://github.com/python/cpython/blob/master/Lib/sre_compile.py

import sys
from sre_parse import SubPattern
from typing import Any, List, Pattern, Tuple, Type, TypeVar, Union

MAXCODE: int
if sys.version_info < (3, 0):
    STRING_TYPES: Tuple[Type[str], Type[unicode]]
    _IsStringType = int
else:
    from sre_constants import _NamedIntConstant
    def dis(code: List[_NamedIntConstant]) -> None: ...
    _IsStringType = bool

def isstring(obj: Any) -> _IsStringType: ...
def compile(p: Union[str, bytes, SubPattern], flags: int = ...) -> Pattern[Any]: ...
