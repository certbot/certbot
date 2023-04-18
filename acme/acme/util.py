"""ACME utilities."""
from typing import Any
from typing import Callable
from typing import Dict
from typing import Mapping


def map_keys(dikt: Mapping[Any, Any], func: Callable[[Any], Any]) -> Dict[Any, Any]:
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}
