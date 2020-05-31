# Stubs for user (Python 2)

# Docs: https://docs.python.org/2/library/user.html
# Source: https://hg.python.org/cpython/file/2.7/Lib/user.py
from typing import Any

def __getattr__(name) -> Any: ...
home: str
pythonrc: str
