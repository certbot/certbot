"""Stub file for the '_json' module."""

from typing import Any, Tuple

class make_encoder:
    sort_keys: Any
    skipkeys: Any
    key_separator: Any
    indent: Any
    markers: Any
    default: Any
    encoder: Any
    item_separator: Any
    def __init__(self, markers, default, encoder, indent, key_separator,
                 item_separator, sort_keys, skipkeys, allow_nan) -> None: ...
    def __call__(self, *args, **kwargs) -> Any: ...

class make_scanner:
    object_hook: Any
    object_pairs_hook: Any
    parse_int: Any
    parse_constant: Any
    parse_float: Any
    strict: bool
    # TODO: 'context' needs the attrs above (ducktype), but not __call__.
    def __init__(self, context: make_scanner) -> None: ...
    def __call__(self, string: str, index: int) -> Tuple[Any, int]: ...

def encode_basestring_ascii(s: str) -> str: ...
def scanstring(string: str, end: int, strict: bool = ...) -> Tuple[str, int]: ...
