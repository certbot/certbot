# Stubs for ctypes.util

from typing import Optional
import sys

def find_library(name: str) -> Optional[str]: ...
if sys.platform == 'win32':
    def find_msvcrt() -> Optional[str]: ...
