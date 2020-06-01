# Source(py2): https://hg.python.org/cpython/file/2.7/Lib/codeop.py
# Source(py3): https://github.com/python/cpython/blob/master/Lib/codeop.py

from types import CodeType
from typing import Optional

def compile_command(source: str, filename: str = ..., symbol: str = ...) -> Optional[CodeType]: ...

class Compile:
    flags: int
    def __init__(self) -> None: ...
    def __call__(self, source: str, filename: str, symbol: str) -> CodeType: ...

class CommandCompiler:
    compiler: Compile
    def __init__(self) -> None: ...
    def __call__(self, source: str, filename: str = ..., symbol: str = ...) -> Optional[CodeType]: ...
