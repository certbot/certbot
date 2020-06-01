# Stubs for sndhdr (Python 2 and 3)

import os
import sys
from typing import Any, NamedTuple, Optional, Tuple, Union

if sys.version_info >= (3, 5):
    class SndHeaders(NamedTuple):
        filetype: str
        framerate: int
        nchannels: int
        nframes: int
        sampwidth: Union[int, str]
    _SndHeaders = SndHeaders
else:
    _SndHeaders = Tuple[str, int, int, int, Union[int, str]]

if sys.version_info >= (3, 6):
    _Path = Union[str, bytes, os.PathLike[Any]]
else:
    _Path = Union[str, bytes]

def what(filename: _Path) -> Optional[_SndHeaders]: ...
def whathdr(filename: _Path) -> Optional[_SndHeaders]: ...
