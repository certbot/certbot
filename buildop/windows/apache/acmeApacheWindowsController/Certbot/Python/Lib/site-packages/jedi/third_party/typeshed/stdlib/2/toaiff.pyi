# Stubs for toaiff (Python 2)

# Source: https://hg.python.org/cpython/file/2.7/Lib/toaiff.py
from pipes import Template
from typing import Dict, List

table: Dict[str, Template]
t: Template
uncompress: Template

class error(Exception): ...

def toaiff(filename: str) -> str: ...
def _toaiff(filename: str, temps: List[str]) -> str: ...
