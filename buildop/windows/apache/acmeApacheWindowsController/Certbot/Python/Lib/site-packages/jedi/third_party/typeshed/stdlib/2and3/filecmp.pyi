# Stubs for filecmp (Python 2/3)
import sys
from typing import AnyStr, Callable, Dict, Generic, Iterable, List, Optional, Sequence, Tuple, Union, Text

DEFAULT_IGNORES: List[str]

def cmp(f1: Union[bytes, Text], f2: Union[bytes, Text], shallow: Union[int, bool] = ...) -> bool: ...
def cmpfiles(a: AnyStr, b: AnyStr, common: Iterable[AnyStr],
             shallow: Union[int, bool] = ...) -> Tuple[List[AnyStr], List[AnyStr], List[AnyStr]]: ...

class dircmp(Generic[AnyStr]):
    def __init__(self, a: AnyStr, b: AnyStr,
                 ignore: Optional[Sequence[AnyStr]] = ...,
                 hide: Optional[Sequence[AnyStr]] = ...) -> None: ...

    left: AnyStr
    right: AnyStr
    hide: Sequence[AnyStr]
    ignore: Sequence[AnyStr]

    # These properties are created at runtime by __getattr__
    subdirs: Dict[AnyStr, dircmp[AnyStr]]
    same_files: List[AnyStr]
    diff_files: List[AnyStr]
    funny_files: List[AnyStr]
    common_dirs: List[AnyStr]
    common_files: List[AnyStr]
    common_funny: List[AnyStr]
    common: List[AnyStr]
    left_only: List[AnyStr]
    right_only: List[AnyStr]
    left_list: List[AnyStr]
    right_list: List[AnyStr]

    def report(self) -> None: ...
    def report_partial_closure(self) -> None: ...
    def report_full_closure(self) -> None: ...

    methodmap: Dict[str, Callable[[], None]]
    def phase0(self) -> None: ...
    def phase1(self) -> None: ...
    def phase2(self) -> None: ...
    def phase3(self) -> None: ...
    def phase4(self) -> None: ...
    def phase4_closure(self) -> None: ...

if sys.version_info >= (3,):
    def clear_cache() -> None: ...
