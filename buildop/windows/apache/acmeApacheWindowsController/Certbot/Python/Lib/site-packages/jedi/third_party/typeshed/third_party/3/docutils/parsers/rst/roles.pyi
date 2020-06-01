import docutils.nodes
import docutils.parsers.rst.states

from typing import Callable, Any, List, Dict, Tuple

_RoleFn = Callable[
    [str, str, str, int, docutils.parsers.rst.states.Inliner, Dict[str, Any], List[str]],
    Tuple[List[docutils.nodes.reference], List[docutils.nodes.reference]],
]

def register_local_role(name: str, role_fn: _RoleFn) -> None: ...

def __getattr__(name: str) -> Any: ...  # incomplete
