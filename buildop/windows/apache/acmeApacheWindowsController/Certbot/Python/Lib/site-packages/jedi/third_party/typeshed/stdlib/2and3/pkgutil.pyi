# Stubs for pkgutil

from typing import Any, Callable, Generator, IO, Iterable, Optional, Tuple, NamedTuple
import sys

if sys.version_info >= (3,):
    from importlib.abc import Loader
else:
    Loader = Any

if sys.version_info >= (3, 6):
    class ModuleInfo(NamedTuple):
        module_finder: Any
        name: str
        ispkg: bool
    _YMFNI = Generator[ModuleInfo, None, None]
else:
    _YMFNI = Generator[Tuple[Any, str, bool], None, None]


def extend_path(path: Iterable[str], name: str) -> Iterable[str]: ...

class ImpImporter:
    def __init__(self, dirname: Optional[str] = ...) -> None: ...

class ImpLoader:
    def __init__(self, fullname: str, file: IO[str], filename: str,
                 etc: Tuple[str, str, int]) -> None: ...

def find_loader(fullname: str) -> Optional[Loader]: ...
def get_importer(path_item: str) -> Any: ...  # TODO precise type
def get_loader(module_or_name: str) -> Loader: ...
def iter_importers(fullname: str = ...) -> Generator[Any, None, None]: ...  # TODO precise type
def iter_modules(path: Optional[Iterable[str]] = ...,
                 prefix: str = ...) -> _YMFNI: ...  # TODO precise type
def walk_packages(path: Optional[Iterable[str]] = ..., prefix: str = ...,
                  onerror: Optional[Callable[[str], None]] = ...) -> _YMFNI: ...
def get_data(package: str, resource: str) -> Optional[bytes]: ...
