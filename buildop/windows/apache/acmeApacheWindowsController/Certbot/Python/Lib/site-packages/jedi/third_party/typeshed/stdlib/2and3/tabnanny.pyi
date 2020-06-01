# Stubs for tabnanny (Python 2 and 3)

import os
import sys
from typing import Iterable, Tuple, Union

if sys.version_info >= (3, 6):
    _Path = Union[str, bytes, os.PathLike]
else:
    _Path = Union[str, bytes]

verbose: int
filename_only: int

class NannyNag(Exception):
    def __init__(self, lineno: int, msg: str, line: str) -> None: ...
    def get_lineno(self) -> int: ...
    def get_msg(self) -> str: ...
    def get_line(self) -> str: ...

def check(file: _Path) -> None: ...
def process_tokens(tokens: Iterable[Tuple[int, str, Tuple[int, int], Tuple[int, int], str]]) -> None: ...
