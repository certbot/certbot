from typing import Any, List

class reference:
    def __init__(self,
                 rawsource: str = ...,
                 text: str = ...,
                 *children: List[Any],
                 **attributes) -> None: ...

def __getattr__(name) -> Any: ...
