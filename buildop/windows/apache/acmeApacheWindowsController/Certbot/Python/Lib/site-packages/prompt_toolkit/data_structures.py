from typing import NamedTuple

__all__ = [
    "Point",
    "Size",
]


Point = NamedTuple("Point", [("x", int), ("y", int)])
Size = NamedTuple("Size", [("rows", int), ("columns", int)])
