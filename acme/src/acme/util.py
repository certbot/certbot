"""ACME utilities."""
from typing import Any
from typing import Callable
from typing import Mapping


def map_keys(dikt: Mapping[Any, Any], func: Callable[[Any], Any]) -> dict[Any, Any]:
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}


def is_wildcard_domain(domain: str) -> bool:
    """"Is domain a wildcard domain?

    :param domain: domain to check
    :type domain: `str`

    :returns: True if domain is a wildcard, otherwise, False
    :rtype: bool

    """
    return domain.startswith("*.")
