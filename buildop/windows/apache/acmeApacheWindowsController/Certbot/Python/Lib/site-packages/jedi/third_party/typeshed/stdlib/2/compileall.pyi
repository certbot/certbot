# Stubs for compileall (Python 2)

from typing import Any, Optional, Pattern, Union

_Path = Union[str, bytes]

# rx can be any object with a 'search' method; once we have Protocols we can change the type
def compile_dir(
    dir: _Path,
    maxlevels: int = ...,
    ddir: Optional[_Path] = ...,
    force: bool = ...,
    rx: Optional[Pattern[Any]] = ...,
    quiet: int = ...,
) -> int: ...
def compile_file(
    fullname: _Path, ddir: Optional[_Path] = ..., force: bool = ..., rx: Optional[Pattern[Any]] = ..., quiet: int = ...,
) -> int: ...
def compile_path(skip_curdir: bool = ..., maxlevels: int = ..., force: bool = ..., quiet: int = ...) -> int: ...
