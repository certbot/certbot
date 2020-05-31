import os
import sys

# 'bytes' paths are not properly supported: they don't work with all functions,
# sometimes they only work partially (broken exception messages), and the test
# cases don't use them.

from typing import (
    List, Iterable, Callable, Any, Tuple, Sequence, NamedTuple, IO,
    AnyStr, Optional, Union, Set, TypeVar, overload, Type, Protocol, Text
)

if sys.version_info >= (3, 6):
    _Path = Union[str, os.PathLike[str]]
    _AnyStr = str
    _AnyPath = TypeVar("_AnyPath", str, os.PathLike[str])
    # Return value of some functions that may either return a path-like object that was passed in or
    # a string
    _PathReturn = Any
elif sys.version_info >= (3,):
    _Path = str
    _AnyStr = str
    _AnyPath = str
    _PathReturn = str
else:
    _Path = Text
    _AnyStr = TypeVar("_AnyStr", str, unicode)
    _AnyPath = TypeVar("_AnyPath", str, unicode)
    _PathReturn = Type[None]

if sys.version_info >= (3,):
    class Error(OSError): ...
    class SameFileError(Error): ...
    class SpecialFileError(OSError): ...
    class ExecError(OSError): ...
    class ReadError(OSError): ...
    class RegistryError(Exception): ...
else:
    class Error(EnvironmentError): ...
    class SpecialFileError(EnvironmentError): ...
    class ExecError(EnvironmentError): ...

_S_co = TypeVar("_S_co", covariant=True)
_S_contra = TypeVar("_S_contra", contravariant=True)

class _Reader(Protocol[_S_co]):
    def read(self, length: int) -> _S_co: ...

class _Writer(Protocol[_S_contra]):
    def write(self, data: _S_contra) -> Any: ...

def copyfileobj(fsrc: _Reader[AnyStr], fdst: _Writer[AnyStr],
                length: int = ...) -> None: ...

if sys.version_info >= (3,):
    def copyfile(src: _Path, dst: _AnyPath, *,
                 follow_symlinks: bool = ...) -> _AnyPath: ...
    def copymode(src: _Path, dst: _Path, *,
                 follow_symlinks: bool = ...) -> None: ...
    def copystat(src: _Path, dst: _Path, *,
                 follow_symlinks: bool = ...) -> None: ...
    def copy(src: _Path, dst: _Path, *,
             follow_symlinks: bool = ...) -> _PathReturn: ...
    def copy2(src: _Path, dst: _Path, *,
              follow_symlinks: bool = ...) -> _PathReturn: ...
else:
    def copyfile(src: _Path, dst: _Path) -> None: ...
    def copymode(src: _Path, dst: _Path) -> None: ...
    def copystat(src: _Path, dst: _Path) -> None: ...
    def copy(src: _Path, dst: _Path) -> _PathReturn: ...
    def copy2(src: _Path, dst: _Path) -> _PathReturn: ...

def ignore_patterns(*patterns: _Path) -> Callable[[Any, List[_AnyStr]], Set[_AnyStr]]: ...

if sys.version_info >= (3, 8):
    def copytree(
        src: _Path,
        dst: _Path,
        symlinks: bool = ...,
        ignore: Union[None, Callable[[str, List[str]], Iterable[str]], Callable[[_Path, List[str]], Iterable[str]]] = ...,
        copy_function: Callable[[str, str], None] = ...,
        ignore_dangling_symlinks: bool = ...,
        dirs_exist_ok: bool = ...,
    ) -> _PathReturn: ...
elif sys.version_info >= (3,):
    def copytree(src: _Path, dst: _Path, symlinks: bool = ...,
                 ignore: Union[None,
                               Callable[[str, List[str]], Iterable[str]],
                               Callable[[_Path, List[str]], Iterable[str]]] = ...,
                 copy_function: Callable[[str, str], None] = ...,
                 ignore_dangling_symlinks: bool = ...) -> _PathReturn: ...
else:
    def copytree(src: AnyStr, dst: AnyStr, symlinks: bool = ...,
                 ignore: Union[None,
                               Callable[[AnyStr, List[AnyStr]],
                                        Iterable[AnyStr]]] = ...) -> _PathReturn: ...

if sys.version_info >= (3,):
    @overload
    def rmtree(path: bytes, ignore_errors: bool = ...,
               onerror: Optional[Callable[[Any, str, Any], Any]] = ...) -> None: ...
    @overload
    def rmtree(path: _AnyPath, ignore_errors: bool = ...,
               onerror: Optional[Callable[[Any, _AnyPath, Any], Any]] = ...) -> None: ...
else:
    def rmtree(path: _AnyPath, ignore_errors: bool = ...,
               onerror: Optional[Callable[[Any, _AnyPath, Any], Any]] = ...) -> None: ...

if sys.version_info >= (3, 5):
    _CopyFn = Union[Callable[[str, str], None], Callable[[_Path, _Path], None]]
    def move(src: _Path, dst: _Path,
             copy_function: _CopyFn = ...) -> _PathReturn: ...
else:
    def move(src: _Path, dst: _Path) -> _PathReturn: ...

if sys.version_info >= (3,):
    class _ntuple_diskusage(NamedTuple):
        total: int
        used: int
        free: int
    def disk_usage(path: _Path) -> _ntuple_diskusage: ...
    def chown(path: _Path, user: Optional[str] = ...,
              group: Optional[str] = ...) -> None: ...
    def which(cmd: _Path, mode: int = ...,
              path: Optional[_Path] = ...) -> Optional[str]: ...

def make_archive(base_name: _AnyStr, format: str, root_dir: Optional[_Path] = ...,
                 base_dir: Optional[_Path] = ..., verbose: bool = ...,
                 dry_run: bool = ..., owner: Optional[str] = ..., group: Optional[str] = ...,
                 logger: Optional[Any] = ...) -> _AnyStr: ...
def get_archive_formats() -> List[Tuple[str, str]]: ...

def register_archive_format(name: str, function: Callable[..., Any],
                            extra_args: Optional[Sequence[Union[Tuple[str, Any], List[Any]]]] = ...,
                            description: str = ...) -> None: ...
def unregister_archive_format(name: str) -> None: ...

if sys.version_info >= (3,):
    # Should be _Path once http://bugs.python.org/issue30218 is fixed
    def unpack_archive(filename: str, extract_dir: Optional[_Path] = ...,
                       format: Optional[str] = ...) -> None: ...
    def register_unpack_format(name: str, extensions: List[str], function: Any,
                               extra_args: Sequence[Tuple[str, Any]] = ...,
                               description: str = ...) -> None: ...
    def unregister_unpack_format(name: str) -> None: ...
    def get_unpack_formats() -> List[Tuple[str, List[str], str]]: ...

    def get_terminal_size(fallback: Tuple[int, int] = ...) -> os.terminal_size: ...
