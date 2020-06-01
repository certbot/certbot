# Stubs for tracemalloc (Python 3.4+)

import sys
from typing import List, Optional, Sequence, Tuple, Union, overload

def clear_traces() -> None: ...
def get_object_traceback(obj: object) -> Optional[Traceback]: ...
def get_traceback_limit() -> int: ...
def get_traced_memory() -> Tuple[int, int]: ...
def get_tracemalloc_memory() -> int: ...
def is_tracing() -> bool: ...
def start(nframe: int = ...) -> None: ...
def stop() -> None: ...
def take_snapshot() -> Snapshot: ...

if sys.version_info >= (3, 6):
    class DomainFilter:
        inclusive: bool
        domain: int
        def __init__(self, inclusive: bool, domain: int) -> None: ...

class Filter:
    if sys.version_info >= (3, 6):
        domain: Optional[int]
    inclusive: bool
    lineno: Optional[int]
    filename_pattern: str
    all_frames: bool
    def __init__(self, inclusive: bool, filename_pattern: str, lineno: Optional[int] = ..., all_frames: bool = ..., domain: Optional[int] = ...) -> None: ...

class Frame:
    filename: str
    lineno: int

class Snapshot:
    def compare_to(self, old_snapshot: Snapshot, key_type: str, cumulative: bool = ...) -> List[StatisticDiff]: ...
    def dump(self, filename: str) -> None: ...
    if sys.version_info >= (3, 6):
        def filter_traces(self, filters: Sequence[Union[DomainFilter, Filter]]) -> Snapshot: ...
    else:
        def filter_traces(self, filters: Sequence[Filter]) -> Snapshot: ...
    @classmethod
    def load(cls, filename: str) -> Snapshot: ...
    def statistics(self, key_type: str, cumulative: bool = ...) -> List[Statistic]: ...
    traceback_limit: int
    traces: Sequence[Trace]

class Statistic:
    count: int
    size: int
    traceback: Traceback

class StatisticDiff:
    count: int
    count_diff: int
    size: int
    size_diff: int
    traceback: Traceback

class Trace:
    size: int
    traceback: Traceback

class Traceback(Sequence[Frame]):
    def format(self, limit: Optional[int] = ...) -> List[str]: ...
    @overload
    def __getitem__(self, i: int) -> Frame: ...
    @overload
    def __getitem__(self, s: slice) -> Sequence[Frame]: ...
    def __len__(self) -> int: ...
